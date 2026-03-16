"""UploadPartCopy SSE-C tests with empty string header values.

Tests whether AWS distinguishes between a missing SSE-C header
and a header present with an empty string value ("") for both
destination and source SSE-C header groups in UploadPartCopy.
"""

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info


# =============================================================================
# Section A: Destination Empty Values (plain source -> SSE-C MPU with empties)
# =============================================================================


@pytest.mark.s3_handler("UploadPartCopy")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestUploadPartCopySSECDestEmptyValues:
    """Test UploadPartCopy with empty string destination SSE-C header values."""

    @pytest.fixture(autouse=True)
    def _part_number(self):
        if not hasattr(self.__class__, "_pn_counter"):
            self.__class__._pn_counter = 0
        self.__class__._pn_counter += 1
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
    # Combo tests: one field empty, others valid
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_algorithm_with_valid_key_and_md5(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Empty dest algorithm + valid key + valid MD5."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_key_with_valid_algorithm_and_md5(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Valid dest algorithm + empty key + valid MD5."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_md5_with_valid_algorithm_and_key(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Valid dest algorithm + valid key + empty MD5."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    # =========================================================================
    # All three empty
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_all_three_headers_empty(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """All three dest SSE-C headers present but empty."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    # =========================================================================
    # Single empty header only (others absent)
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_algorithm_only(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Only dest algorithm header present but empty."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_key_only(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Only dest key header present but empty."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-key": "",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dest_empty_md5_only(
        self, test_bucket, plain_source, ssec_multipart_upload, make_request, json_metadata, request,
    ):
        """Only dest MD5 header present but empty."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload, headers, self._pn,
        )

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


# =============================================================================
# Section B: Source Empty Values (SSE-C source -> plain MPU with empties)
# =============================================================================


@pytest.mark.s3_handler("UploadPartCopy")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestUploadPartCopySSECSourceEmptyValues:
    """Test UploadPartCopy with empty string source SSE-C header values."""

    @pytest.fixture(autouse=True)
    def _part_number(self):
        if not hasattr(self.__class__, "_pn_counter"):
            self.__class__._pn_counter = 0
        self.__class__._pn_counter += 1
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
    # Combo tests: one field empty, others valid
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_algorithm_with_valid_key_and_md5(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Empty source algorithm + valid key + valid MD5."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_key_with_valid_algorithm_and_md5(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Valid source algorithm + empty key + valid MD5."""
        _, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": "",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_md5_with_valid_algorithm_and_key(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Valid source algorithm + valid key + empty MD5."""
        key_b64, _ = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    # =========================================================================
    # All three empty
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_all_three_headers_empty(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """All three source SSE-C headers present but empty."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "",
            "x-amz-copy-source-server-side-encryption-customer-key": "",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    # =========================================================================
    # Single empty header only (others absent)
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_algorithm_only(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Only source algorithm header present but empty."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_key_only(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Only source key header present but empty."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-key": "",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_source_empty_md5_only(
        self, test_bucket, ssec_source, plain_multipart_upload, make_request, json_metadata, request,
    ):
        """Only source MD5 header present but empty."""
        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": "",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload, headers, self._pn,
        )

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
