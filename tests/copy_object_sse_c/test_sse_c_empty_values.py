"""CopyObject SSE-C tests with empty string header values.

Tests whether AWS distinguishes between a missing SSE-C header
and a header present with an empty string value ("") for both
destination and source SSE-C header groups.
"""

import base64
import hashlib
import os
import uuid

import pytest

from s3_compliance.client import S3ClientFactory
from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info


COPY_BODY = b"copy-object sse-c empty values test"


# =============================================================================
# Module-scoped fixtures
# =============================================================================


@pytest.fixture(scope="module")
def plain_source_key():
    return f"test-copy-empty-plain-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def ssec_source_key():
    return f"test-copy-empty-ssec-{uuid.uuid4().hex[:8]}"


@pytest.fixture(scope="module")
def dest_key_prefix():
    return f"test-copy-empty-dst-{uuid.uuid4().hex[:8]}"


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
# Section A: Destination Empty Values (plain source -> SSE-C dest with empties)
# =============================================================================


@pytest.mark.s3_handler("CopyObject")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestCopyObjectSSECDestEmptyValues:
    """Test CopyObject with empty string destination SSE-C header values."""

    @pytest.fixture(autouse=True)
    def _dest_key(self, dest_key_prefix):
        self._dk = f"{dest_key_prefix}-dempty-{uuid.uuid4().hex[:4]}"

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
    # Combo tests: one field empty, others valid
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_algorithm_with_valid_key_and_md5(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Empty dest algorithm + valid key + valid MD5."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "dest_algorithm"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_key_with_valid_algorithm_and_md5(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Valid dest algorithm + empty key + valid MD5."""
        endpoint_mode = request.config.getoption("--endpoint")
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "dest_key"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_md5_with_valid_algorithm_and_key(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Valid dest algorithm + valid key + empty MD5."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "dest_md5"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    # =========================================================================
    # All three empty
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_all_three_headers_empty(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """All three dest SSE-C headers present but empty."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "dest_all"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    # =========================================================================
    # Single empty header only (others absent)
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_algorithm_only(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Only dest algorithm header present but empty."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "dest_algorithm_only"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_key_only(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Only dest key header present but empty."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-key": "",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "dest_key_only"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_md5_only(
        self, aws_client, test_bucket, plain_source, make_request, json_metadata, request,
    ):
        """Only dest MD5 header present but empty."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "dest_md5_only"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)


# =============================================================================
# Section B: Source Empty Values (SSE-C source -> plain dest with empties)
# =============================================================================


@pytest.mark.s3_handler("CopyObject")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestCopyObjectSSECSourceEmptyValues:
    """Test CopyObject with empty string source SSE-C header values."""

    @pytest.fixture(autouse=True)
    def _dest_key(self, dest_key_prefix):
        self._dk = f"{dest_key_prefix}-sempty-{uuid.uuid4().hex[:4]}"

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
    # Combo tests: one field empty, others valid
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_algorithm_with_valid_key_and_md5(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Empty source algorithm + valid key + valid MD5."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "source_algorithm"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_key_with_valid_algorithm_and_md5(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Valid source algorithm + empty key + valid MD5."""
        endpoint_mode = request.config.getoption("--endpoint")
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "source_key"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_md5_with_valid_algorithm_and_key(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Valid source algorithm + valid key + empty MD5."""
        endpoint_mode = request.config.getoption("--endpoint")
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "source_md5"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    # =========================================================================
    # All three empty
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_all_three_headers_empty(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """All three source SSE-C headers present but empty."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "",
            "x-amz-copy-source-server-side-encryption-customer-key": "",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "source_all"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    # =========================================================================
    # Single empty header only (others absent)
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_algorithm_only(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Only source algorithm header present but empty."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "source_algorithm_only"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_key_only(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Only source key header present but empty."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-key": "",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "source_key_only"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_md5_only(
        self, aws_client, test_bucket, ssec_source, make_request, json_metadata, request,
    ):
        """Only source MD5 header present but empty."""
        endpoint_mode = request.config.getoption("--endpoint")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "",
        }

        response = make_request("PUT", f"/{test_bucket}/{self._dk}", headers=headers)

        json_metadata["empty_field"] = "source_md5_only"

        if hasattr(response, "comparison"):
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["aws_error_code"] = error_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code

        self._cleanup(aws_client, test_bucket, endpoint_mode)
