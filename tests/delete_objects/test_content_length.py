"""Tests for DeleteObjects Content-Length header handling.

These tests verify S3 behavior with various Content-Length header edge cases:
- Normal Content-Length
- Empty Content-Length header
- Missing Content-Length header
- Mismatched Content-Length (larger than actual body)
"""

import uuid
from xml.etree import ElementTree as ET

import pytest
import requests

from s3_compliance.signing import sign_request
from s3_compliance.utils import calculate_content_md5, calculate_content_sha256


S3_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


def parse_delete_response(response_text: str) -> dict:
    """Parse DeleteObjects XML response."""
    result = {"deleted": [], "errors": []}
    try:
        root = ET.fromstring(response_text)
        for deleted in root.findall(f".//{S3_NS}Deleted"):
            key_elem = deleted.find(f"{S3_NS}Key")
            if key_elem is not None:
                result["deleted"].append(key_elem.text)

        for error in root.findall(f".//{S3_NS}Error"):
            err_info = {}
            code_elem = error.find(f"{S3_NS}Code")
            if code_elem is not None:
                err_info["code"] = code_elem.text
            result["errors"].append(err_info)
    except ET.ParseError:
        pass
    return result


@pytest.mark.delete_objects
@pytest.mark.s3_handler("DeleteObjects")
class TestDeleteObjectsContentLength:
    """Test DeleteObjects API with Content-Length header edge cases."""

    @pytest.fixture
    def test_key(self):
        """Generate unique test key."""
        return f"test-content-length-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def test_content(self):
        """Test content."""
        return b"test content for content-length tests"

    @pytest.fixture
    def test_object(self, s3_client, test_bucket, test_key, test_content):
        """Create test object."""
        s3_client.put_object(Bucket=test_bucket, Key=test_key, Body=test_content)

        yield test_key

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=test_key)
        except Exception:
            pass

    def _build_delete_xml(self, key: str) -> bytes:
        """Build DeleteObjects XML body."""
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Object>
        <Key>{key}</Key>
    </Object>
</Delete>'''
        return xml.encode("utf-8")

    def test_normal_content_length(
        self,
        test_bucket,
        test_object,
        endpoint_url,
        credentials,
        region,
    ):
        """Normal DeleteObjects request with correct Content-Length - should succeed."""
        body = self._build_delete_xml(test_object)
        url = f"{endpoint_url}/{test_bucket}?delete"

        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": calculate_content_md5(body),
            "Content-Length": str(len(body)),
            "x-amz-content-sha256": calculate_content_sha256(body),
        }

        signed_headers = sign_request(
            method="POST",
            url=url,
            headers=headers,
            body=body,
            credentials=credentials,
            region=region,
        )

        response = requests.post(url, data=body, headers=signed_headers, verify=False)

        assert response.status_code == 200
        result = parse_delete_response(response.text)
        assert test_object in result["deleted"]

    @pytest.mark.edge_case
    def test_empty_content_length(
        self,
        test_bucket,
        test_object,
        endpoint_url,
        credentials,
        region,
        json_metadata,
    ):
        """DeleteObjects with empty Content-Length header value."""
        body = self._build_delete_xml(test_object)
        url = f"{endpoint_url}/{test_bucket}?delete"

        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": calculate_content_md5(body),
            "Content-Length": "",  # Empty Content-Length
            "x-amz-content-sha256": calculate_content_sha256(body),
        }

        signed_headers = sign_request(
            method="POST",
            url=url,
            headers=headers,
            body=body,
            credentials=credentials,
            region=region,
        )

        response = requests.post(url, data=body, headers=signed_headers, verify=False)

        json_metadata["status_code"] = response.status_code
        json_metadata["content_length_value"] = "empty"

        # AWS may accept or reject
        if response.status_code == 200:
            result = parse_delete_response(response.text)
            json_metadata["deleted"] = result["deleted"]
            assert test_object in result["deleted"]
        else:
            # Server rejected - document the behavior
            json_metadata["error_response"] = response.text[:500]

    @pytest.mark.edge_case
    def test_missing_content_length(
        self,
        test_bucket,
        test_object,
        endpoint_url,
        credentials,
        region,
        json_metadata,
    ):
        """DeleteObjects without Content-Length header."""
        body = self._build_delete_xml(test_object)
        url = f"{endpoint_url}/{test_bucket}?delete"

        # Build headers without Content-Length
        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": calculate_content_md5(body),
            "x-amz-content-sha256": calculate_content_sha256(body),
        }

        signed_headers = sign_request(
            method="POST",
            url=url,
            headers=headers,
            body=body,
            credentials=credentials,
            region=region,
        )

        # Remove Content-Length if signing added it
        if "Content-Length" in signed_headers:
            del signed_headers["Content-Length"]

        response = requests.post(url, data=body, headers=signed_headers, verify=False)

        json_metadata["status_code"] = response.status_code
        json_metadata["content_length_value"] = "missing"

        # AWS typically requires Content-Length (411 Length Required)
        # But some servers may accept chunked encoding
        if response.status_code == 200:
            result = parse_delete_response(response.text)
            json_metadata["deleted"] = result["deleted"]
        elif response.status_code == 411:
            json_metadata["behavior"] = "requires_content_length"

        # Document behavior - either accepted or required Content-Length
        assert response.status_code in [200, 411, 400]

    @pytest.mark.edge_case
    def test_large_content_length_small_body(
        self,
        test_bucket,
        test_object,
        endpoint_url,
        credentials,
        region,
        json_metadata,
    ):
        """DeleteObjects with large Content-Length but small actual body.

        Tests server behavior when Content-Length indicates 5GB but
        actual XML body is small.
        """
        body = self._build_delete_xml(test_object)
        url = f"{endpoint_url}/{test_bucket}?delete"

        large_content_length = 5 * 1024 * 1024 * 1024  # 5GB

        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": calculate_content_md5(body),
            "Content-Length": str(large_content_length),  # Mismatched
            "x-amz-content-sha256": calculate_content_sha256(body),
        }

        json_metadata["actual_body_size"] = len(body)
        json_metadata["claimed_content_length"] = large_content_length

        signed_headers = sign_request(
            method="POST",
            url=url,
            headers=headers,
            body=body,
            credentials=credentials,
            region=region,
        )

        response = requests.post(url, data=body, headers=signed_headers, verify=False)

        json_metadata["status_code"] = response.status_code

        # Server should either:
        # 1. Accept the request (using actual body)
        # 2. Reject with 400 (Content-Length mismatch)
        # 3. Wait for more data (timeout)
        if response.status_code == 200:
            result = parse_delete_response(response.text)
            json_metadata["behavior"] = "accepted_despite_mismatch"
            json_metadata["deleted"] = result["deleted"]
        elif response.status_code == 400:
            json_metadata["behavior"] = "rejected_mismatch"

        # Document behavior (403 = SignatureDoesNotMatch when Content-Length mismatches body)
        assert response.status_code in [200, 400, 403, 408]

    @pytest.mark.edge_case
    def test_zero_content_length(
        self,
        test_bucket,
        test_object,
        endpoint_url,
        credentials,
        region,
        json_metadata,
    ):
        """DeleteObjects with Content-Length: 0 but non-empty body."""
        body = self._build_delete_xml(test_object)
        url = f"{endpoint_url}/{test_bucket}?delete"

        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": calculate_content_md5(body),
            "Content-Length": "0",  # Zero but body is not empty
            "x-amz-content-sha256": calculate_content_sha256(body),
        }

        json_metadata["actual_body_size"] = len(body)
        json_metadata["claimed_content_length"] = 0

        signed_headers = sign_request(
            method="POST",
            url=url,
            headers=headers,
            body=body,
            credentials=credentials,
            region=region,
        )

        response = requests.post(url, data=body, headers=signed_headers, verify=False)

        json_metadata["status_code"] = response.status_code

        # Server should reject this - body present but Content-Length says 0
        # Expected: 400 Bad Request or similar
        if response.status_code == 200:
            json_metadata["behavior"] = "accepted_despite_zero_length"
        else:
            json_metadata["behavior"] = "rejected_zero_length"

        # Document behavior (403 = SignatureDoesNotMatch when Content-Length mismatches body)
        assert response.status_code in [200, 400, 403, 411]
