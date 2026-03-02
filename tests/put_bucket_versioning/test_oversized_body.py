"""Tests for PutBucketVersioning with oversized request bodies.

Verifies S3 behavior when receiving bodies exceeding expected size limits.
Two approaches: XML comment padding (valid XML) and null-byte prefix (invalid XML).

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import (
    build_null_prefixed_xml,
    build_versioning_xml_padded,
)


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningOversizedBody:
    """Test PutBucketVersioning with oversized request bodies."""

    @pytest.mark.edge_case
    @pytest.mark.slow
    @pytest.mark.parametrize(
        "target_bytes",
        [
            pytest.param(1_048_576, id="1MB_exact"),
            pytest.param(1_048_577, id="1MB_plus_1"),
            pytest.param(2 * 1024**2, id="2MB"),
        ],
    )
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_oversized_xml_comment_padded(
        self, target_bytes, test_bucket, make_request, json_metadata
    ):
        """Valid XML padded with XML comment beyond 1MB."""
        body = build_versioning_xml_padded("Enabled", target_bytes=target_bytes)
        headers = {"Content-Type": "application/xml"}

        json_metadata["payload_size_bytes"] = len(body)

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.slow
    @pytest.mark.parametrize(
        "prefix_bytes",
        [
            pytest.param(1_048_576, id="1MB_null_prefix"),
            pytest.param(2 * 1024**2, id="2MB_null_prefix"),
        ],
    )
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_byte_prefix_body(
        self, prefix_bytes, test_bucket, make_request, json_metadata
    ):
        """Null bytes before valid XML (mimics generate_huge_xml.py pattern)."""
        body = build_null_prefixed_xml("Enabled", prefix_bytes=prefix_bytes)
        headers = {"Content-Type": "application/xml"}

        json_metadata["payload_size_bytes"] = len(body)

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg
