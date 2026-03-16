"""Tests for UploadPartCopy SSE-C cross-group validation order.

When both source and destination SSE-C header groups have errors,
which group/header does S3 validate first?

Strategy: use DISTINGUISHABLE errors per group so we can tell from the
error code/message which group triggered the rejection.

- Dest error: invalid algorithm "DEST-INVALID" -> expect InvalidEncryptionAlgorithmError
  with ArgumentValue "DEST-INVALID"
- Source error: only algorithm header, missing key/md5 -> expect InvalidArgument
  "must provide an appropriate secret key"

If the response mentions "DEST-INVALID" -> dest validated first.
If the response mentions "secret key" -> source validated first.
"""

import re

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info


def extract_argument_value(response_text: str) -> str | None:
    """Extract ArgumentValue from S3 XML error response."""
    match = re.search(r"<ArgumentValue>([^<]+)</ArgumentValue>", response_text)
    return match.group(1) if match else None


@pytest.mark.s3_handler("UploadPartCopy")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestUploadPartCopyCrossValidationOrder:
    """Probe which SSE-C header group S3 validates first when both have errors.

    Uses distinguishable errors:
    - Dest: invalid algorithm "DEST-INVALID" (-> InvalidEncryptionAlgorithmError)
    - Source: only algorithm, missing key/md5 (-> InvalidArgument "secret key")
    """

    _part_counter = 0

    @pytest.fixture(autouse=True)
    def _increment_part(self):
        TestUploadPartCopyCrossValidationOrder._part_counter += 1

    def _make_upc_request(self, make_request, request, test_bucket, mpu, headers, part_number):
        """Make an UploadPartCopy request via make_request fixture."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            query_params = f"?uploadId={mpu['aws']}&partNumber={part_number}"
            custom_query_params = f"?uploadId={mpu['custom']}&partNumber={part_number}"
        else:
            query_params = f"?uploadId={mpu['upload_id']}&partNumber={part_number}"
            custom_query_params = None

        return make_request(
            "PUT",
            f"/{test_bucket}/{mpu['key']}",
            headers=headers,
            query_params=query_params,
            custom_query_params=custom_query_params,
        )

    # =========================================================================
    # Test 1: Both groups have distinguishable errors
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_both_groups_different_errors(
        self, test_bucket, ssec_source, ssec_multipart_upload,
        make_request, json_metadata, request,
    ):
        """Dest has invalid algo "DEST-INVALID", source has only algo (missing key/md5).

        If error mentions "DEST-INVALID" -> dest validated first.
        If error mentions "secret key" -> source validated first.
        """
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            # Source group -- only algorithm, missing key and md5
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            # Dest group -- invalid algorithm with valid key/md5
            "x-amz-server-side-encryption-customer-algorithm": "DEST-INVALID",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload,
            headers, part_number=self._part_counter,
        )

        json_metadata["dest_error_type"] = "invalid_algo_DEST-INVALID"
        json_metadata["source_error_type"] = "missing_key_and_md5"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            arg_value = extract_argument_value(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["aws_argument_value"] = arg_value
            json_metadata["validated_first"] = (
                "dest" if arg_value == "DEST-INVALID" else "source"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            arg_value = extract_argument_value(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            json_metadata["argument_value"] = arg_value
            json_metadata["validated_first"] = (
                "dest" if arg_value == "DEST-INVALID" else "source"
            )

    # =========================================================================
    # Test 2: Swap -- source has invalid algo, dest has missing key
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_both_groups_swapped_errors(
        self, test_bucket, ssec_source, ssec_multipart_upload,
        make_request, json_metadata, request,
    ):
        """Source has invalid algo "SRC-INVALID", dest has only algo (missing key/md5).

        If error mentions "SRC-INVALID" -> source validated first.
        If error mentions "secret key" -> dest validated first.
        """
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            # Source group -- invalid algorithm with valid key/md5
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "SRC-INVALID",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
            # Dest group -- only algorithm, missing key and md5
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload,
            headers, part_number=self._part_counter,
        )

        json_metadata["source_error_type"] = "invalid_algo_SRC-INVALID"
        json_metadata["dest_error_type"] = "missing_key_and_md5"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            arg_value = extract_argument_value(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["aws_argument_value"] = arg_value
            json_metadata["validated_first"] = (
                "source" if arg_value == "SRC-INVALID" else "dest"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            arg_value = extract_argument_value(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            json_metadata["argument_value"] = arg_value
            json_metadata["validated_first"] = (
                "source" if arg_value == "SRC-INVALID" else "dest"
            )

    # =========================================================================
    # Test 3: Both groups have invalid algo with unique values
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_both_invalid_algo_unique_values(
        self, test_bucket, ssec_source, ssec_multipart_upload,
        make_request, json_metadata, request,
    ):
        """Both groups have invalid algo: dest="DEST-ALG", source="SRC-ALG".

        ArgumentValue in response tells us which group was checked first.
        """
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            # Source group -- invalid algo
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "SRC-ALG",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
            # Dest group -- invalid algo
            "x-amz-server-side-encryption-customer-algorithm": "DEST-ALG",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload,
            headers, part_number=self._part_counter,
        )

        json_metadata["source_algo"] = "SRC-ALG"
        json_metadata["dest_algo"] = "DEST-ALG"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            arg_value = extract_argument_value(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["aws_argument_value"] = arg_value
            if arg_value:
                json_metadata["validated_first"] = (
                    "dest" if "DEST" in arg_value else "source"
                )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            arg_value = extract_argument_value(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            json_metadata["argument_value"] = arg_value
            if arg_value:
                json_metadata["validated_first"] = (
                    "dest" if "DEST" in arg_value else "source"
                )
