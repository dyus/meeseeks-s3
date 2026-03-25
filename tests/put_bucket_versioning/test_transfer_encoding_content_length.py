"""Tests for PutBucketVersioning Transfer-Encoding + Content-Length interaction.

Verifies how AWS S3 handles the combination of Transfer-Encoding and Content-Length.
Both headers are sent simultaneously thanks to forced header preservation in _do_request.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest
import requests as requests_lib

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml


VALID_BODY = build_versioning_xml("Enabled")


def chunked_encode(data: bytes) -> bytes:
    """Encode data in HTTP chunked transfer encoding format."""
    return f"{len(data):x}\r\n".encode() + data + b"\r\n0\r\n\r\n"


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestTransferEncodingContentLengthInteraction:
    """Test Transfer-Encoding + Content-Length header interaction."""

    # --- TE: chunked + raw body (not chunked-encoded) ---

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_chunked_te_with_raw_body_connection_reset(
        self, test_bucket, make_request, json_metadata,
    ):
        """TE: chunked + CL: actual + raw body — AWS resets connection.

        Body is raw XML, not chunked-encoded. AWS tries chunked decoding, fails.
        """
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "chunked",
            "Content-Length": str(len(VALID_BODY)),
        }

        json_metadata["transfer_encoding"] = "chunked"
        json_metadata["content_length"] = len(VALID_BODY)
        json_metadata["body_encoding"] = "raw (not chunked)"

        with pytest.raises(requests_lib.exceptions.ConnectionError):
            make_request(
                "PUT",
                f"/{test_bucket}",
                body=VALID_BODY,
                headers=headers,
                query_params="?versioning",
            )

        json_metadata["result"] = "ConnectionError (remote closed)"

    # --- TE: chunked + properly chunked body + CL: encoded size ---

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_chunked_te_with_chunked_body_cl_encoded_size(
        self, test_bucket, make_request, json_metadata,
    ):
        """TE: chunked + CL: encoded_size + chunked-encoded body.

        Both headers present. CL matches the chunked-encoded body size.
        AWS should ignore CL per HTTP spec, decode chunked, parse XML.
        """
        encoded_body = chunked_encode(VALID_BODY)
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "chunked",
            "Content-Length": str(len(encoded_body)),
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=encoded_body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "chunked"
        json_metadata["content_length"] = len(encoded_body)
        json_metadata["raw_body_size"] = len(VALID_BODY)

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400 and response.text:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code

    # --- TE: chunked + chunked body + CL: raw (non-encoded) size ---

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_chunked_te_with_chunked_body_cl_raw_size(
        self, test_bucket, make_request, json_metadata,
    ):
        """TE: chunked + CL: raw_size (161) + chunked-encoded body (172 bytes).

        CL doesn't match actual body. AWS should ignore CL when TE is present.
        """
        encoded_body = chunked_encode(VALID_BODY)
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "chunked",
            "Content-Length": str(len(VALID_BODY)),  # raw size, not encoded
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=encoded_body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "chunked"
        json_metadata["content_length_sent"] = len(VALID_BODY)
        json_metadata["actual_body_size"] = len(encoded_body)

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400 and response.text:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code

    # --- TE: chunked + chunked body + CL: 0 ---

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_chunked_te_with_chunked_body_cl_zero(
        self, test_bucket, make_request, json_metadata,
    ):
        """TE: chunked + CL: 0 + chunked-encoded body.

        CL says empty, but TE: chunked + actual body present. Which wins?
        """
        encoded_body = chunked_encode(VALID_BODY)
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "chunked",
            "Content-Length": "0",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=encoded_body,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "chunked"
        json_metadata["content_length"] = 0
        json_metadata["actual_body_size"] = len(encoded_body)

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400 and response.text:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code

    # --- TE: chunked + empty body + CL: 0 ---

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_chunked_te_empty_body_cl_zero(
        self, test_bucket, make_request, json_metadata,
    ):
        """TE: chunked + CL: 0 + empty body. Both agree: no data."""
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "chunked",
            "Content-Length": "0",
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=b"",
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "chunked"
        json_metadata["content_length"] = 0
        json_metadata["body"] = "empty"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400 and response.text:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code

    # --- TE: chunked + chunked terminator only + CL: 5 ---

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_chunked_te_terminator_only(
        self, test_bucket, make_request, json_metadata,
    ):
        """TE: chunked + CL: 5 + chunked terminator (0\\r\\n\\r\\n).

        Valid empty chunked body (zero-length final chunk).
        """
        terminator = b"0\r\n\r\n"
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "chunked",
            "Content-Length": str(len(terminator)),
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=terminator,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "chunked"
        json_metadata["content_length"] = len(terminator)
        json_metadata["body"] = "chunked terminator only"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400 and response.text:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code

    # --- TE: invalid + valid body + CL ---

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_te_with_valid_body(
        self, test_bucket, make_request, json_metadata,
    ):
        """TE: xyz + CL: actual + valid body — invalid TE rejected."""
        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "xyz",
            "Content-Length": str(len(VALID_BODY)),
        }

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=VALID_BODY,
            headers=headers,
            query_params="?versioning",
        )

        json_metadata["transfer_encoding"] = "xyz"
        json_metadata["content_length"] = len(VALID_BODY)

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400 and response.text:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
