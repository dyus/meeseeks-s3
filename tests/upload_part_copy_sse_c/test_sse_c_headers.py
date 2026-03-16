"""Tests for UploadPartCopy SSE-C header validation.

UploadPartCopy has two independent groups of SSE-C headers:

Destination headers (encrypt the copied part in MPU):
- x-amz-server-side-encryption-customer-algorithm
- x-amz-server-side-encryption-customer-key
- x-amz-server-side-encryption-customer-key-MD5

Source headers (decrypt the source object):
- x-amz-copy-source-server-side-encryption-customer-algorithm
- x-amz-copy-source-server-side-encryption-customer-key
- x-amz-copy-source-server-side-encryption-customer-key-MD5

Section A tests destination headers (plain source -> SSE-C dest MPU).
Section B tests source headers (SSE-C source -> plain dest MPU).
"""

import base64
import hashlib

import pytest

from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info


# =============================================================================
# Section A: Destination SSE-C Headers (plain source -> SSE-C dest MPU)
# =============================================================================


@pytest.mark.s3_handler("UploadPartCopy")
@pytest.mark.sse_c
class TestUploadPartCopySSECDestHeaders:
    """Test destination SSE-C header validation for UploadPartCopy.

    Source is plain (no source SSE-C headers needed).
    Only x-amz-server-side-encryption-customer-* varies.
    """

    _pn_counter = 0

    @pytest.fixture(autouse=True)
    def _part_number(self):
        TestUploadPartCopySSECDestHeaders._pn_counter += 1
        self._pn = self.__class__._pn_counter

    def _make_upc_request(self, make_request, request, test_bucket, mpu, headers, part_number):
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            query_params = f"?uploadId={mpu['aws']}&partNumber={part_number}"
            custom_query_params = f"?uploadId={mpu['custom']}&partNumber={part_number}"
        else:
            query_params = f"?uploadId={mpu['upload_id']}&partNumber={part_number}"
            custom_query_params = None
        return make_request(
            "PUT", f"/{test_bucket}/{mpu['key']}",
            headers=headers, query_params=query_params,
            custom_query_params=custom_query_params,
        )

    # =========================================================================
    # Missing Header Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_only_algorithm(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with only dest algorithm header."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_only_key(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with only dest key header."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_only_key_md5(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with only dest key MD5 header."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_algorithm_and_key_missing_md5(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with dest algorithm + key but missing MD5."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_algorithm_and_md5_missing_key(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with dest algorithm + MD5 but missing key."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_key_and_md5_missing_algorithm(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with dest key + MD5 but missing algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    # =========================================================================
    # Invalid Value Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_invalid_algorithm(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with invalid dest algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_short_key_10_bytes(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with dest key too short (10 bytes)."""
        short_key = b"1234567890"
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_mismatched_md5(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy when dest key MD5 doesn't match key."""
        key_b64, _ = generate_sse_c_key()
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong-key").digest()).decode("utf-8")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_invalid_base64_md5(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy when dest key MD5 is not valid base64."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "not-valid-base64!!!",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    # =========================================================================
    # Validation Priority Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_all_invalid_validation_order(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """All dest headers invalid -- check which error takes priority."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-server-side-encryption-customer-key": "c2hvcnQta2V5",
            "x-amz-server-side-encryption-customer-key-MD5": "K9opmNmw7hl9oUKgRH9nJQ==",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_invalid_key_base64_with_invalid_algorithm(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Invalid algorithm + invalid base64 key -- check priority."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "INVALID-ALGO",
            "x-amz-server-side-encryption-customer-key": "not-valid-base64!!!",
            "x-amz-server-side-encryption-customer-key-MD5": "8OFm3DTRTWwij/rFdsmkPA==",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_invalid_key_length_with_invalid_algorithm(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Invalid algorithm + short key (10 bytes) -- check priority."""
        key_b64, key_md5 = generate_sse_c_key(b"1234567890")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "INVALID-ALGO",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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


# =============================================================================
# Section B: Source SSE-C Headers (SSE-C source -> plain dest MPU)
# =============================================================================


@pytest.mark.s3_handler("UploadPartCopy")
@pytest.mark.sse_c
class TestUploadPartCopySSECSourceHeaders:
    """Test source SSE-C header validation for UploadPartCopy.

    Dest is plain (no dest SSE-C headers).
    Only x-amz-copy-source-server-side-encryption-customer-* varies.
    """

    _pn_counter = 0

    @pytest.fixture(autouse=True)
    def _part_number(self):
        TestUploadPartCopySSECSourceHeaders._pn_counter += 1
        self._pn = self.__class__._pn_counter

    def _make_upc_request(self, make_request, request, test_bucket, mpu, headers, part_number):
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            query_params = f"?uploadId={mpu['aws']}&partNumber={part_number}"
            custom_query_params = f"?uploadId={mpu['custom']}&partNumber={part_number}"
        else:
            query_params = f"?uploadId={mpu['upload_id']}&partNumber={part_number}"
            custom_query_params = None
        return make_request(
            "PUT", f"/{test_bucket}/{mpu['key']}",
            headers=headers, query_params=query_params,
            custom_query_params=custom_query_params,
        )

    # =========================================================================
    # Missing Header Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_only_algorithm(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with only source algorithm header."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_only_key(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with only source key header."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_only_key_md5(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with only source key MD5 header."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_algorithm_and_key_missing_md5(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """UploadPartCopy with source algorithm + key but missing MD5 succeeds.

        Unlike destination SSE-C, AWS does NOT require MD5 for source SSE-C
        when algorithm + key are provided. Returns 200.
        """
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

        json_metadata["provided_headers"] = ["source_algorithm", "source_key"]
        json_metadata["missing_headers"] = ["source_key_md5"]

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200
            json_metadata["status"] = response.status_code

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_algorithm_and_md5_missing_key(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with source algorithm + MD5 but missing key."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_key_and_md5_missing_algorithm(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with source key + MD5 but missing algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    # =========================================================================
    # Invalid Value Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_invalid_algorithm(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with invalid source algorithm."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES128-INVALID",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_short_key_10_bytes(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy with source key too short (10 bytes)."""
        short_key = b"1234567890"
        key_b64, key_md5 = generate_sse_c_key(short_key)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_mismatched_md5(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy when source key MD5 doesn't match key."""
        key_b64, _ = generate_sse_c_key()
        wrong_md5 = base64.b64encode(hashlib.md5(b"wrong-key").digest()).decode("utf-8")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": wrong_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_invalid_base64_md5(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Reject UploadPartCopy when source key MD5 is not valid base64."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "not-valid-base64!!!",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    # =========================================================================
    # Validation Priority Tests
    # =========================================================================

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_all_invalid_validation_order(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """All source headers invalid -- check which error takes priority."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256-INVALID",
            "x-amz-copy-source-server-side-encryption-customer-key": "c2hvcnQta2V5",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "K9opmNmw7hl9oUKgRH9nJQ==",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_invalid_key_base64_with_invalid_algorithm(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Invalid algorithm + invalid base64 key -- check priority."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "INVALID-ALGO",
            "x-amz-copy-source-server-side-encryption-customer-key": "not-valid-base64!!!",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "8OFm3DTRTWwij/rFdsmkPA==",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_invalid_key_length_with_invalid_algorithm(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Invalid algorithm + short key (10 bytes) -- check priority."""
        key_b64, key_md5 = generate_sse_c_key(b"1234567890")

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "INVALID-ALGO",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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
