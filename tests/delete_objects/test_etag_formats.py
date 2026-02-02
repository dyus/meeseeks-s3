"""Tests for DeleteObjects ETag format handling.

These tests verify S3 behavior with various ETag format edge cases:
- Standard quoted: "etag"
- Double-quoted: ""etag""
- Unquoted: etag
- Weak ETag: W/"etag"
- Empty ETag: ""
- Multiple ETags: "etag1", "etag2"

Supports both single endpoint mode (--endpoint=aws or --endpoint=custom)
and comparison mode (--endpoint=both).
"""

import uuid
from xml.etree import ElementTree as ET

import pytest

from s3_compliance.utils import calculate_content_md5


S3_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def parse_delete_response(response_text: str) -> dict:
    """Parse DeleteObjects XML response.

    Returns:
        dict with 'deleted' and 'errors' lists
    """
    result = {"deleted": [], "errors": []}
    try:
        root = ET.fromstring(response_text)
        for deleted in root.findall(f".//{S3_NS}Deleted"):
            key_elem = deleted.find(f"{S3_NS}Key")
            if key_elem is not None:
                result["deleted"].append(key_elem.text)

        for error in root.findall(f".//{S3_NS}Error"):
            err_info = {}
            key_elem = error.find(f"{S3_NS}Key")
            code_elem = error.find(f"{S3_NS}Code")
            message_elem = error.find(f"{S3_NS}Message")
            if key_elem is not None:
                err_info["key"] = key_elem.text
            if code_elem is not None:
                err_info["code"] = code_elem.text
            if message_elem is not None:
                err_info["message"] = message_elem.text
            result["errors"].append(err_info)
    except ET.ParseError:
        pass
    return result


@pytest.mark.delete_objects
@pytest.mark.s3_handler("DeleteObjects")
class TestDeleteObjectsEtagFormats:
    """Test DeleteObjects API with various ETag format edge cases."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-etag-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def test_content(self):
        """Test content."""
        return b"test content for etag tests"

    @pytest.fixture
    def test_object(self, s3_client, test_bucket, test_key, test_content):
        """Create test object and return its ETag."""
        response = s3_client.put_object(
            Bucket=test_bucket, Key=test_key, Body=test_content
        )
        etag = response.get("ETag", "").strip('"')

        yield {"key": test_key, "etag": etag}

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    def _build_delete_xml(self, key: str, etag_value: str) -> bytes:
        """Build DeleteObjects XML with specific ETag format."""
        xml_body = f'''<?xml version="1.0" encoding="UTF-8"?>
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Object>
        <Key>{key}</Key>
        <ETag>{etag_value}</ETag>
    </Object>
</Delete>'''
        return xml_body.encode("utf-8")

    def _make_delete_request(self, make_request, test_bucket, key, etag_value):
        """Make DeleteObjects request with specific ETag format."""
        body = self._build_delete_xml(key, etag_value)
        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": calculate_content_md5(body),
        }
        return make_request(
            "POST",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?delete",
        )

    @pytest.mark.edge_case
    def test_standard_quoted_etag(
        self,
        test_bucket,
        test_object,
        make_request,
        json_metadata,
    ):
        """Standard ETag format with quotes: "etag" - should succeed."""
        etag_value = f'"{test_object["etag"]}"'
        json_metadata["etag_format"] = "standard_quoted"
        json_metadata["etag_value"] = etag_value

        response = self._make_delete_request(
            make_request, test_bucket, test_object["key"], etag_value
        )

        if hasattr(response, "comparison"):
            # Comparison mode
            assert response.aws.status_code == 200
            result = parse_delete_response(response.aws.text)
            assert test_object["key"] in result["deleted"], (
                f"AWS expected object to be deleted, got errors: {result['errors']}"
            )
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
            assert response.status_code == 200
            result = parse_delete_response(response.text)
            assert test_object["key"] in result["deleted"], (
                f"Expected object to be deleted, got errors: {result['errors']}"
            )

    @pytest.mark.edge_case
    def test_double_quoted_etag(
        self,
        test_bucket,
        test_object,
        make_request,
        json_metadata,
    ):
        """Double-quoted ETag: ""etag"" - AWS behavior varies."""
        etag_value = f'""{test_object["etag"]}""'
        json_metadata["etag_format"] = "double_quoted"
        json_metadata["etag_value"] = etag_value

        response = self._make_delete_request(
            make_request, test_bucket, test_object["key"], etag_value
        )

        if hasattr(response, "comparison"):
            # Comparison mode - document behavior
            json_metadata["aws_status_code"] = response.aws.status_code
            result = parse_delete_response(response.aws.text)
            json_metadata["deleted"] = result["deleted"]
            json_metadata["errors"] = result["errors"]
            # AWS may accept or reject
            assert response.aws.status_code in [200, 400]
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
            json_metadata["status_code"] = response.status_code
            result = parse_delete_response(response.text)
            json_metadata["deleted"] = result["deleted"]
            json_metadata["errors"] = result["errors"]
            assert response.status_code in [200, 400]

    @pytest.mark.edge_case
    def test_unquoted_etag(
        self,
        test_bucket,
        test_object,
        make_request,
        json_metadata,
    ):
        """Unquoted ETag: etag - how does S3 handle?"""
        etag_value = test_object["etag"]  # No quotes
        json_metadata["etag_format"] = "unquoted"
        json_metadata["etag_value"] = etag_value

        response = self._make_delete_request(
            make_request, test_bucket, test_object["key"], etag_value
        )

        if hasattr(response, "comparison"):
            # Comparison mode
            json_metadata["aws_status_code"] = response.aws.status_code
            result = parse_delete_response(response.aws.text)
            json_metadata["deleted"] = result["deleted"]
            json_metadata["errors"] = result["errors"]
            assert response.aws.status_code in [200, 400]
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
            json_metadata["status_code"] = response.status_code
            result = parse_delete_response(response.text)
            json_metadata["deleted"] = result["deleted"]
            json_metadata["errors"] = result["errors"]
            assert response.status_code in [200, 400]

    @pytest.mark.edge_case
    def test_weak_etag(
        self,
        test_bucket,
        test_object,
        make_request,
        json_metadata,
    ):
        """Weak ETag format: W/"etag" - HTTP spec format."""
        etag_value = f'W/"{test_object["etag"]}"'
        json_metadata["etag_format"] = "weak"
        json_metadata["etag_value"] = etag_value

        response = self._make_delete_request(
            make_request, test_bucket, test_object["key"], etag_value
        )

        if hasattr(response, "comparison"):
            # Comparison mode
            json_metadata["aws_status_code"] = response.aws.status_code
            result = parse_delete_response(response.aws.text)
            json_metadata["deleted"] = result["deleted"]
            json_metadata["errors"] = result["errors"]
            assert response.aws.status_code in [200, 400]
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
            json_metadata["status_code"] = response.status_code
            result = parse_delete_response(response.text)
            json_metadata["deleted"] = result["deleted"]
            json_metadata["errors"] = result["errors"]
            assert response.status_code in [200, 400]

    @pytest.mark.edge_case
    def test_empty_etag(
        self,
        test_bucket,
        test_object,
        make_request,
        json_metadata,
    ):
        """Empty ETag: "" - edge case."""
        etag_value = '""'
        json_metadata["etag_format"] = "empty"
        json_metadata["etag_value"] = etag_value

        response = self._make_delete_request(
            make_request, test_bucket, test_object["key"], etag_value
        )

        if hasattr(response, "comparison"):
            # Comparison mode
            json_metadata["aws_status_code"] = response.aws.status_code
            result = parse_delete_response(response.aws.text)
            json_metadata["deleted"] = result["deleted"]
            json_metadata["errors"] = result["errors"]
            assert response.aws.status_code in [200, 400]
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
            json_metadata["status_code"] = response.status_code
            result = parse_delete_response(response.text)
            json_metadata["deleted"] = result["deleted"]
            json_metadata["errors"] = result["errors"]
            assert response.status_code in [200, 400]

    @pytest.mark.edge_case
    def test_multiple_etags_comma_separated(
        self,
        test_bucket,
        test_object,
        make_request,
        json_metadata,
    ):
        """Multiple ETags comma-separated: "etag1", "etag2" - like HTTP headers."""
        fake_etag = "00000000000000000000000000000000"
        etag_value = f'"{test_object["etag"]}", "{fake_etag}"'
        json_metadata["etag_format"] = "multiple_comma"
        json_metadata["etag_value"] = etag_value

        response = self._make_delete_request(
            make_request, test_bucket, test_object["key"], etag_value
        )

        if hasattr(response, "comparison"):
            # Comparison mode
            json_metadata["aws_status_code"] = response.aws.status_code
            result = parse_delete_response(response.aws.text)
            json_metadata["deleted"] = result["deleted"]
            json_metadata["errors"] = result["errors"]
            assert response.aws.status_code in [200, 400]
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
            json_metadata["status_code"] = response.status_code
            result = parse_delete_response(response.text)
            json_metadata["deleted"] = result["deleted"]
            json_metadata["errors"] = result["errors"]
            assert response.status_code in [200, 400]

    @pytest.mark.edge_case
    def test_mismatched_etag(
        self,
        test_bucket,
        test_object,
        make_request,
        json_metadata,
    ):
        """Completely wrong ETag - should fail precondition."""
        etag_value = '"00000000000000000000000000000000"'
        json_metadata["etag_format"] = "mismatched"
        json_metadata["etag_value"] = etag_value

        response = self._make_delete_request(
            make_request, test_bucket, test_object["key"], etag_value
        )

        if hasattr(response, "comparison"):
            # Comparison mode
            json_metadata["aws_status_code"] = response.aws.status_code
            result = parse_delete_response(response.aws.text)
            # Should fail with PreconditionFailed or similar
            assert response.aws.status_code == 200  # DeleteObjects returns 200 with errors
            assert len(result["errors"]) > 0, "Expected precondition error"
            assert any(
                err.get("code") in ["PreconditionFailed", "InvalidDigest"]
                for err in result["errors"]
            ), f"Expected PreconditionFailed error, got: {result['errors']}"
            assert response.comparison.is_compliant, (
                f"Custom S3 doesn't match AWS: {response.diff_summary}"
            )
        else:
            # Single endpoint mode
            json_metadata["status_code"] = response.status_code
            result = parse_delete_response(response.text)
            # Should fail with PreconditionFailed or similar
            assert response.status_code == 200  # DeleteObjects returns 200 with errors
            assert len(result["errors"]) > 0, "Expected precondition error"
            assert any(
                err.get("code") in ["PreconditionFailed", "InvalidDigest"]
                for err in result["errors"]
            ), f"Expected PreconditionFailed error, got: {result['errors']}"
