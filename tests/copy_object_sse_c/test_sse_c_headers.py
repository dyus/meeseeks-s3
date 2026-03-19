"""Tests for CopyObject SSE-C header validation.

CopyObject has two independent groups of SSE-C headers:

Destination headers (encrypt the new copy):
- x-amz-server-side-encryption-customer-algorithm
- x-amz-server-side-encryption-customer-key
- x-amz-server-side-encryption-customer-key-MD5

Source headers (decrypt the source object):
- x-amz-copy-source-server-side-encryption-customer-algorithm
- x-amz-copy-source-server-side-encryption-customer-key
- x-amz-copy-source-server-side-encryption-customer-key-MD5

Section A tests destination headers (plain source -> SSE-C dest).
Section B tests source headers (SSE-C source -> plain dest).
"""

import base64
import hashlib
import os
import uuid

import pytest

from s3_compliance.client import S3ClientFactory
from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info


COPY_BODY = b"copy-object sse-c header validation test"


# =============================================================================
# Module-scoped fixtures
# =============================================================================


@pytest.fixture(scope="module")
def plain_source_key():
    return f"test-copy-hdr-plain-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def ssec_source_key():
    return f"test-copy-hdr-ssec-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def dest_key_prefix():
    return f"test-copy-hdr-dst-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def plain_source(request, aws_client, test_bucket, setup_test_bucket, plain_source_key):
    """Create a plain source object on each endpoint."""
    endpoint_mode = request.config.getoption("--endpoint")

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    kwargs = dict(Bucket=test_bucket, Key=plain_source_key, Body=COPY_BODY)

    if endpoint_mode in ("aws", "both"):
        aws_client.put_object(**kwargs)
    if custom_cl:
        custom_cl.put_object(**kwargs)

    yield plain_source_key

    if endpoint_mode in ("aws", "both"):
        try:
            aws_client.delete_object(Bucket=test_bucket, Key=plain_source_key)
        except Exception:
            pass
    if custom_cl:
        try:
            custom_cl.delete_object(Bucket=test_bucket, Key=plain_source_key)
        except Exception:
            pass


@pytest.fixture(scope="module")
def ssec_source(request, aws_client, test_bucket, setup_test_bucket, ssec_source_key):
    """Create an SSE-C encrypted source object on each endpoint."""
    endpoint_mode = request.config.getoption("--endpoint")
    key_b64, key_md5 = generate_sse_c_key()

    sse_kwargs = dict(
        Bucket=test_bucket,
        Key=ssec_source_key,
        Body=COPY_BODY,
        SSECustomerAlgorithm="AES256",
        SSECustomerKey=key_b64,
        SSECustomerKeyMD5=key_md5,
    )

    custom_cl = None
    if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
        custom_cl = S3ClientFactory().create_client("custom")

    def _add_forwarded_proto(params, **kwargs):
        params["headers"]["X-Forwarded-Proto"] = "https"

    if endpoint_mode in ("aws", "both"):
        aws_client.put_object(**sse_kwargs)
    if custom_cl:
        custom_cl.meta.events.register("before-call.s3.PutObject", _add_forwarded_proto)
        custom_cl.put_object(**sse_kwargs)
        custom_cl.meta.events.unregister("before-call.s3.PutObject", _add_forwarded_proto)

    yield ssec_source_key

    if endpoint_mode in ("aws", "both"):
        try:
            aws_client.delete_object(Bucket=test_bucket, Key=ssec_source_key)
        except Exception:
            pass
    if custom_cl:
        try:
            custom_cl.delete_object(Bucket=test_bucket, Key=ssec_source_key)
        except Exception:
            pass


# =============================================================================
# Section A: Destination SSE-C Headers (plain source -> SSE-C dest)
# =============================================================================


@pytest.mark.s3_handler("CopyObject")
@pytest.mark.sse_c
class TestCopyObjectSSECDestHeaders:
    """Test destination SSE-C header validation for CopyObject.

    Source is plain (no source SSE-C headers needed).
    Only x-amz-server-side-encryption-customer-* varies.
    """

    @pytest.fixture(autouse=True)
    def _dest_key(self, dest_key_prefix):
        self._dk = f"{dest_key_prefix}-dest-{uuid.uuid4().hex[:4]}"

    def _cleanup(self, aws_client, test_bucket, endpoint_mode):
        if endpoint_mode in ("aws", "both"):
            try:
                aws_client.delete_object(Bucket=test_bucket, Key=self._dk)
            except Exception:
                pass
        if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
            try:
                cl = S3ClientFactory().create_client("custom")
                cl.delete_object(Bucket=test_bucket, Key=self._dk)
            except Exception:
                pass

    # =========================================================================
    # Missing Header Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_only_algorithm(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with only dest algorithm header."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["provided_headers"] = ["dest_algorithm"]
        json_metadata["missing_headers"] = ["dest_key", "dest_key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_only_key(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with only dest key header."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["provided_headers"] = ["dest_key"]
        json_metadata["missing_headers"] = ["dest_algorithm", "dest_key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_only_key_md5(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with only dest key MD5 header."""
        endpoint_mode = request.config.getoption("--endpoint")
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["provided_headers"] = ["dest_key_md5"]
        json_metadata["missing_headers"] = ["dest_algorithm", "dest_key"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_algorithm_and_key_missing_md5(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with dest algorithm + key but missing MD5."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["provided_headers"] = ["dest_algorithm", "dest_key"]
        json_metadata["missing_headers"] = ["dest_key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_algorithm_and_md5_missing_key(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with dest algorithm + MD5 but missing key."""
        endpoint_mode = request.config.getoption("--endpoint")
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["provided_headers"] = ["dest_algorithm", "dest_key_md5"]
        json_metadata["missing_headers"] = ["dest_key"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_key_and_md5_missing_algorithm(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with dest key + MD5 but missing algorithm."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["provided_headers"] = ["dest_key", "dest_key_md5"]
        json_metadata["missing_headers"] = ["dest_algorithm"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    # =========================================================================
    # Invalid Value Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_invalid_algorithm(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with invalid dest algorithm."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["invalid_algorithm"] = "AES128-INVALID"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_short_key_10_bytes(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with dest key too short (10 bytes)."""
        endpoint_mode = request.config.getoption("--endpoint")
        short_key = b"1234567890"
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_length_bytes"] = 10

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_mismatched_md5(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject when dest key MD5 doesn't match key."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong-key").digest()).decode("utf-8")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_md5_matches_key"] = False

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_invalid_base64_md5(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject when dest key MD5 is not valid base64."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "not-valid-base64!!!",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["invalid_base64_md5"] = "not-valid-base64!!!"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    # =========================================================================
    # Validation Priority Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_all_invalid_validation_order(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """All dest headers invalid — check which error takes priority."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-server-side-encryption-customer-key": "c2hvcnQta2V5",
            "x-amz-server-side-encryption-customer-key-MD5": "K9opmNmw7hl9oUKgRH9nJQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["all_invalid"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_invalid_key_base64_with_invalid_algorithm(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Invalid algorithm + invalid base64 key — check priority."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "INVALID-ALGO",
            "x-amz-server-side-encryption-customer-key": "not-valid-base64!!!",
            "x-amz-server-side-encryption-customer-key-MD5": "8OFm3DTRTWwij/rFdsmkPA==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["invalid_algorithm"] = "INVALID-ALGO"
        json_metadata["invalid_key_base64"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_invalid_key_length_with_invalid_algorithm(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Invalid algorithm + short key (10 bytes) — check priority."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key(b"1234567890")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "INVALID-ALGO",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["invalid_algorithm"] = "INVALID-ALGO"
        json_metadata["key_length_bytes"] = 10

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_invalid_key_length_with_mismatched_md5(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Valid algorithm + short key + mismatched MD5 — check priority."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64 = generate_sse_c_key(b"1234567890")[0]

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "K9opmNmw7hl9oUKgRH9nJQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_length_bytes"] = 10
        json_metadata["md5_mismatched"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_all_invalid_headers_over_http(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """All invalid dest headers over HTTP (not HTTPS)."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-server-side-encryption-customer-key": "c2hvcnQta2V5",
            "x-amz-server-side-encryption-customer-key-MD5": "K9opmNmw7hl9oUKgRH9nJQ==",
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{self._dk}", headers=headers, scheme="http",
        )

        json_metadata["scheme"] = "http"
        json_metadata["all_invalid"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_valid_with_sse_s3_conflict(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Valid dest SSE-C + x-amz-server-side-encryption: AES256 (SSE-S3 conflict)."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption": "AES256",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["sse_s3_conflict"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    # =========================================================================
    # Key Encoding Edge Cases
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_customer_key_decodes_to_short_value(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key '####' decodes to short value."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "####",
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = "####"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_customer_key_zz(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key 'ZZ' — short base64 value."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "ZZ",
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = "ZZ"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_customer_key_single_char_a(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key 'a' — single character."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "a",
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = "a"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_customer_key_latin1_chars(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key with latin1 characters — expect 403."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "\u00e9\u00f1\u00fc\u00df",
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = "\u00e9\u00f1\u00fc\u00df"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 403
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 403
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_customer_key(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key is empty string."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = ""

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    @pytest.mark.parametrize(
        "variant_name, key_value",
        [
            ("garbage-at-end", "K0+/yQHJcx5CgotqScZJqhfJ8hpfw4leiB3Bzyo8HSo=!!!!#"),
            ("garbage-at-start", "!!!!#K0+/yQHJcx5CgotqScZJqhfJ8hpfw4leiB3Bzyo8HSo="),
            ("garbage-in-middle", "K0+/yQHJcx5CgotqScZJqh!!!!#fJ8hpfw4leiB3Bzyo8HSo="),
            ("garbage-scattered", "!K0+/yQHJ#cx5CgotqScZJ!!qhfJ8hpfw4leiB3Bzyo8HSo=#"),
        ],
    )
    def test_dest_customer_key_with_garbage_chars_in_base64(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
        variant_name, key_value,
    ):
        """Dest key with garbage characters in base64 — AWS may ignore garbage."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_value,
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["variant"] = variant_name
        json_metadata["key_value"] = key_value

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_customer_key_decodes_to_1_byte(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key 'AQ==' decodes to 1 byte."""
        endpoint_mode = request.config.getoption("--endpoint")
        _, key_md5 = generate_sse_c_key(b"\x01")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "AQ==",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = "AQ=="
        json_metadata["decoded_length_bytes"] = 1

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_short_key_zz_with_matching_md5(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key 'ZZ' with matching MD5."""
        endpoint_mode = request.config.getoption("--endpoint")
        decoded_key = base64.b64decode("ZZ==")  # 1 byte: 0x65
        key_md5 = base64.b64encode(
            hashlib.md5(decoded_key).digest()
        ).decode("utf-8")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "ZZ",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = "ZZ"
        json_metadata["md5_matches"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_long_key_33_bytes_with_matching_md5(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key 33 bytes with matching MD5."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key(b"\x01" * 33)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_length_bytes"] = 33

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_key_base64_with_spaces(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key base64 with spaces inserted."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "K0+/ yQHJ cx5C gotq ScZJ qhfJ 8hpf w4le iB3B zyo8 HSo=",
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_has_spaces"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_key_base64_with_tabs_and_newlines(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key base64 with tabs inserted."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "K0+/\tyQHJ\tcx5C\tgotq\tScZJ\tqhfJ\t8hpf\tw4le\tiB3B\tzyo8\tHSo=",
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_has_tabs"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_key_base64_without_padding(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key base64 without padding '='."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "K0+/yQHJcx5CgotqScZJqhfJ8hpfw4leiB3Bzyo8HSo",
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_without_padding"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_key_base64_with_extra_padding(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key base64 with extra padding '===='."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "K0+/yQHJcx5CgotqScZJqhfJ8hpfw4leiB3Bzyo8HSo=====",
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_extra_padding"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_key_url_safe_base64(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key using URL-safe base64 (- and _ instead of + and /)."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "K0-_yQHJcx5CgotqScZJqhfJ8hpfw4leiB3Bzyo8HSo=",
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["url_safe_base64_key"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_key_and_md5_both_url_safe_base64(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key and MD5 both using URL-safe base64."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "K0-_yQHJcx5CgotqScZJqhfJ8hpfw4leiB3Bzyo8HSo=",
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["url_safe_base64_key_and_md5"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_key_31_bytes(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key 31 bytes (one byte short of AES-256)."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key(b"\x01" * 31)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_length_bytes"] = 31

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_key_33_bytes(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest key 33 bytes (one byte over AES-256)."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key(b"\x01" * 33)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_length_bytes"] = 33

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_md5_with_garbage_chars(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest MD5 with garbage characters in base64."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "!!I0aPuXuw##4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["md5_has_garbage"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_md5_decodes_to_wrong_length(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Dest MD5 decodes to wrong length (not 16 bytes)."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "AQEBAQEBAQE=",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["md5_wrong_decoded_length"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_valid_key_md5_without_padding(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Valid dest key but MD5 base64 without padding."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["md5_without_padding"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)


# =============================================================================
# Section B: Source SSE-C Headers (SSE-C source -> plain dest)
# =============================================================================


@pytest.mark.s3_handler("CopyObject")
@pytest.mark.sse_c
class TestCopyObjectSSECSourceHeaders:
    """Test source SSE-C header validation for CopyObject.

    Dest is plain (no dest SSE-C headers).
    Only x-amz-copy-source-server-side-encryption-customer-* varies.
    """

    @pytest.fixture(autouse=True)
    def _dest_key(self, dest_key_prefix):
        self._dk = f"{dest_key_prefix}-src-{uuid.uuid4().hex[:4]}"

    def _cleanup(self, aws_client, test_bucket, endpoint_mode):
        if endpoint_mode in ("aws", "both"):
            try:
                aws_client.delete_object(Bucket=test_bucket, Key=self._dk)
            except Exception:
                pass
        if os.getenv("S3_ENDPOINT") and endpoint_mode in ("custom", "both"):
            try:
                cl = S3ClientFactory().create_client("custom")
                cl.delete_object(Bucket=test_bucket, Key=self._dk)
            except Exception:
                pass

    # =========================================================================
    # Missing Header Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_only_algorithm(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with only source algorithm header."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["provided_headers"] = ["source_algorithm"]
        json_metadata["missing_headers"] = ["source_key", "source_key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_only_key(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with only source key header."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["provided_headers"] = ["source_key"]
        json_metadata["missing_headers"] = ["source_algorithm", "source_key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_only_key_md5(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with only source key MD5 header."""
        endpoint_mode = request.config.getoption("--endpoint")
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["provided_headers"] = ["source_key_md5"]
        json_metadata["missing_headers"] = ["source_algorithm", "source_key"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_algorithm_and_key_missing_md5_accepted(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """AWS accepts source SSE-C with algorithm + key but missing MD5."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["provided_headers"] = ["source_algorithm", "source_key"]
        json_metadata["missing_headers"] = ["source_key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_algorithm_and_md5_missing_key(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with source algorithm + MD5 but missing key."""
        endpoint_mode = request.config.getoption("--endpoint")
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["provided_headers"] = ["source_algorithm", "source_key_md5"]
        json_metadata["missing_headers"] = ["source_key"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_key_and_md5_missing_algorithm(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with source key + MD5 but missing algorithm."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["provided_headers"] = ["source_key", "source_key_md5"]
        json_metadata["missing_headers"] = ["source_algorithm"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    # =========================================================================
    # Invalid Value Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_invalid_algorithm(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with invalid source algorithm."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["invalid_algorithm"] = "AES128-INVALID"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_wrong_key(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with wrong source decryption key (400 InvalidRequest)."""
        endpoint_mode = request.config.getoption("--endpoint")
        # Use a different key than what the source was encrypted with
        wrong_key_bytes = hashlib.sha256(b"wrong_key_for_ssec_source").digest()
        key_b64, key_md5 = generate_sse_c_key(wrong_key_bytes)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["wrong_decryption_key"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_short_key_10_bytes(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject with source key too short (10 bytes)."""
        endpoint_mode = request.config.getoption("--endpoint")
        short_key = b"1234567890"
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_length_bytes"] = 10

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_mismatched_md5(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Reject CopyObject when source key MD5 doesn't match key."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong-key").digest()).decode("utf-8")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_md5_matches_key"] = False

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    # =========================================================================
    # Base64 / Encoding Edge Cases (Source)
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_invalid_base64_md5(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source MD5 is not valid base64 — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "not-valid-base64!!!",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["md5_value"] = "not-valid-base64!!!"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_customer_key_latin1_chars(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key with latin1 characters — expect 403."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "\u00e9\u00f1\u00fc\u00df",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = "\u00e9\u00f1\u00fc\u00df"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 403
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 403
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_customer_key(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key is empty string — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = ""

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    @pytest.mark.parametrize(
        "variant_name, key_value",
        [
            ("garbage-at-end", "K0+/yQHJcx5CgotqScZJqhfJ8hpfw4leiB3Bzyo8HSo=!!!!#"),
            ("garbage-at-start", "!!!!#K0+/yQHJcx5CgotqScZJqhfJ8hpfw4leiB3Bzyo8HSo="),
            ("garbage-in-middle", "K0+/yQHJcx5CgotqScZJqh!!!!#fJ8hpfw4leiB3Bzyo8HSo="),
            ("garbage-scattered", "!K0+/yQHJ#cx5CgotqScZJ!!qhfJ8hpfw4leiB3Bzyo8HSo=#"),
        ],
    )
    def test_source_customer_key_with_garbage_chars_in_base64(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
        variant_name, key_value,
    ):
        """Source key with garbage characters in base64 — AWS may ignore garbage."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_value,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["variant"] = variant_name
        json_metadata["key_value"] = key_value

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_customer_key_decodes_to_1_byte(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key 'AQ==' decodes to 1 byte — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")
        _, key_md5 = generate_sse_c_key(b"\x01")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "AQ==",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = "AQ=="
        json_metadata["decoded_length_bytes"] = 1

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_customer_key_decodes_to_short_value(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key '####' decodes to short value — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "####",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = "####"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_customer_key_zz(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key 'ZZ' — short base64 value — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "ZZ",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = "ZZ"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_customer_key_single_char_a(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key 'a' — single character — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "a",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = "a"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_short_key_zz_with_matching_md5(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key 'ZZ' with matching MD5 — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")
        decoded_key = base64.b64decode("ZZ==")  # 1 byte: 0x65
        key_md5 = base64.b64encode(
            hashlib.md5(decoded_key).digest()
        ).decode("utf-8")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "ZZ",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_value"] = "ZZ"
        json_metadata["md5_matches"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_long_key_33_bytes_with_matching_md5(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key 33 bytes with matching MD5 — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key(b"\x01" * 33)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_length_bytes"] = 33

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_key_base64_with_spaces(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key base64 with spaces inserted."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "K0+/ yQHJ cx5C gotq ScZJ qhfJ 8hpf w4le iB3B zyo8 HSo=",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_has_spaces"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_key_base64_with_tabs_and_newlines(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key base64 with tabs inserted."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "K0+/\tyQHJ\tcx5C\tgotq\tScZJ\tqhfJ\t8hpf\tw4le\tiB3B\tzyo8\tHSo=",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_has_tabs"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_key_base64_without_padding(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key base64 without padding '=' — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "K0+/yQHJcx5CgotqScZJqhfJ8hpfw4leiB3Bzyo8HSo",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_without_padding"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_key_base64_with_extra_padding(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key base64 with extra padding '===='."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "K0+/yQHJcx5CgotqScZJqhfJ8hpfw4leiB3Bzyo8HSo=====",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_extra_padding"] = True

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_key_url_safe_base64(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key using URL-safe base64 (- and _ instead of + and /) — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "K0-_yQHJcx5CgotqScZJqhfJ8hpfw4leiB3Bzyo8HSo=",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["url_safe_base64_key"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_key_and_md5_both_url_safe_base64(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key and MD5 both using URL-safe base64 — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "K0-_yQHJcx5CgotqScZJqhfJ8hpfw4leiB3Bzyo8HSo=",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["url_safe_base64_key_and_md5"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_key_31_bytes(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key 31 bytes (one byte short of AES-256) — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key(b"\x01" * 31)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_length_bytes"] = 31

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_key_33_bytes(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source key 33 bytes (one byte over AES-256) — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key(b"\x01" * 33)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["key_length_bytes"] = 33

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_md5_with_garbage_chars(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source MD5 with garbage characters in base64 — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "!!I0aPuXuw##4REDJuP1fw07QQ==",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["md5_has_garbage"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_md5_decodes_to_wrong_length(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Source MD5 decodes to wrong length (not 16 bytes) — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "AQEBAQEBAQE=",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["md5_wrong_decoded_length"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_valid_key_md5_without_padding(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Valid source key but MD5 base64 without padding — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "I0aPuXuw4REDJuP1fw07QQ",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["md5_without_padding"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_all_invalid_headers_over_http(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """All invalid source headers over HTTP (not HTTPS) — expect 400."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-copy-source-server-side-encryption-customer-key": "c2hvcnQta2V5",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "K9opmNmw7hl9oUKgRH9nJQ==",
        }

        response = make_request(
            "PUT", f"/{test_bucket}/{self._dk}", headers=headers, scheme="http",
        )

        json_metadata["scheme"] = "http"
        json_metadata["all_invalid"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        self._cleanup(aws_client, test_bucket, endpoint_mode)
