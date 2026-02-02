"""Tests for DeleteObjects key encoding and limits.

These tests verify S3 behavior with:
- Special characters requiring XML escaping
- Forbidden/problematic characters
- Key length limits (max 1024 bytes)
- Object count limits (max 1000 per request)
"""

import uuid
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as xml_escape

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
class TestDeleteObjectsKeyEncoding:
    """Test DeleteObjects API with various key encoding edge cases."""

    def _make_delete_request(
        self,
        test_bucket: str,
        keys: list[str],
        endpoint_url: str,
        credentials,
        region: str,
    ) -> requests.Response:
        """Make DeleteObjects request with list of keys."""
        objects_xml = "\n".join(
            f"    <Object>\n        <Key>{xml_escape(key)}</Key>\n    </Object>"
            for key in keys
        )

        xml_body = f'''<?xml version="1.0" encoding="UTF-8"?>
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
{objects_xml}
</Delete>'''

        body_bytes = xml_body.encode("utf-8")
        content_md5 = calculate_content_md5(body_bytes)
        content_sha256 = calculate_content_sha256(body_bytes)

        url = f"{endpoint_url}/{test_bucket}?delete"
        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": content_md5,
            "Content-Length": str(len(body_bytes)),
            "x-amz-content-sha256": content_sha256,
        }

        signed_headers = sign_request(
            method="POST",
            url=url,
            headers=headers,
            body=body_bytes,
            credentials=credentials,
            region=region,
        )

        return requests.post(url, data=body_bytes, headers=signed_headers, verify=False)

    @pytest.mark.edge_case
    @pytest.mark.parametrize(
        "char,char_name",
        [
            ("&", "Ampersand"),
            ("$", "Dollar"),
            ("@", "At sign"),
            ("=", "Equals"),
            (";", "Semicolon"),
            ("/", "Forward slash"),
            (":", "Colon"),
            ("+", "Plus"),
            (" ", "Space"),
            (",", "Comma"),
            ("?", "Question mark"),
        ],
    )
    def test_escaped_character_in_key(
        self,
        s3_client,
        test_bucket,
        char,
        char_name,
        endpoint_url,
        credentials,
        region,
        json_metadata,
    ):
        """Test DeleteObjects with characters requiring XML escaping."""
        test_id = uuid.uuid4().hex[:8]
        key_name = f"test-escaped-{char}-{test_id}"

        json_metadata["character"] = char_name
        json_metadata["key"] = key_name

        # Try to create object first
        try:
            s3_client.put_object(
                Bucket=test_bucket, Key=key_name, Body=b"test content"
            )
            json_metadata["object_created"] = True
        except Exception as e:
            json_metadata["object_created"] = False
            json_metadata["create_error"] = str(e)

        # Make delete request
        response = self._make_delete_request(
            test_bucket, [key_name], endpoint_url, credentials, region
        )

        json_metadata["status_code"] = response.status_code
        result = parse_delete_response(response.text)

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=key_name)
        except Exception:
            pass

        # Request should succeed (200) or object didn't exist
        assert response.status_code == 200

    @pytest.mark.edge_case
    @pytest.mark.parametrize(
        "char,char_name",
        [
            ("\\", "Backslash"),
            ("{", "Opening curly brace"),
            ("}", "Closing curly brace"),
            ("^", "Caret"),
            ("%", "Percent"),
            ("`", "Backtick"),
            ("[", "Opening square bracket"),
            ("]", "Closing square bracket"),
            ('"', "Double quote"),
            (">", "Greater than"),
            ("<", "Less than"),
            ("~", "Tilde"),
            ("#", "Hash"),
            ("|", "Vertical bar"),
        ],
    )
    def test_problematic_character_in_key(
        self,
        s3_client,
        test_bucket,
        char,
        char_name,
        endpoint_url,
        credentials,
        region,
        json_metadata,
    ):
        """Test DeleteObjects with problematic characters."""
        test_id = uuid.uuid4().hex[:8]
        key_name = f"test-problematic-{char}-{test_id}"

        json_metadata["character"] = char_name
        json_metadata["key"] = key_name

        # Try to create object
        try:
            s3_client.put_object(
                Bucket=test_bucket, Key=key_name, Body=b"test content"
            )
            json_metadata["object_created"] = True
        except Exception as e:
            json_metadata["object_created"] = False
            json_metadata["create_error"] = str(e)

        # Make delete request
        response = self._make_delete_request(
            test_bucket, [key_name], endpoint_url, credentials, region
        )

        json_metadata["status_code"] = response.status_code

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=key_name)
        except Exception:
            pass

        # Document behavior - may be accepted or rejected
        assert response.status_code in [200, 400]

    @pytest.mark.edge_case
    def test_key_length_at_limit(
        self,
        test_bucket,
        endpoint_url,
        credentials,
        region,
        json_metadata,
    ):
        """Test DeleteObjects with key exactly at 1024 byte limit."""
        base_key = f"test-key-limit-{uuid.uuid4().hex[:8]}-"
        padding = "x" * (1024 - len(base_key))
        key_1024 = base_key + padding

        json_metadata["key_length"] = len(key_1024)
        assert len(key_1024) == 1024

        response = self._make_delete_request(
            test_bucket, [key_1024], endpoint_url, credentials, region
        )

        json_metadata["status_code"] = response.status_code

        # Should be accepted (1024 is valid)
        assert response.status_code == 200

    @pytest.mark.edge_case
    def test_key_length_exceeds_limit(
        self,
        test_bucket,
        endpoint_url,
        credentials,
        region,
        json_metadata,
    ):
        """Test DeleteObjects with key exceeding 1024 byte limit."""
        base_key = f"test-key-over-limit-{uuid.uuid4().hex[:8]}-"
        padding = "x" * (1025 - len(base_key))
        key_1025 = base_key + padding

        json_metadata["key_length"] = len(key_1025)
        assert len(key_1025) == 1025

        response = self._make_delete_request(
            test_bucket, [key_1025], endpoint_url, credentials, region
        )

        json_metadata["status_code"] = response.status_code
        result = parse_delete_response(response.text)

        # Should be rejected or have error for this key
        if response.status_code == 400:
            json_metadata["behavior"] = "rejected_entire_request"
        elif response.status_code == 200 and result["errors"]:
            json_metadata["behavior"] = "returned_error_for_key"
            json_metadata["error_codes"] = [e.get("code") for e in result["errors"]]
        else:
            json_metadata["behavior"] = "accepted_unexpectedly"

    @pytest.mark.edge_case
    @pytest.mark.slow
    def test_max_object_count_exceeded(
        self,
        test_bucket,
        endpoint_url,
        credentials,
        region,
        json_metadata,
    ):
        """Test DeleteObjects with 1001 objects (exceeds 1000 limit)."""
        keys = [f"test-key-{i:04d}" for i in range(1001)]
        json_metadata["object_count"] = len(keys)

        # Build XML manually to avoid memory issues
        objects_xml = "\n".join(
            f"    <Object>\n        <Key>{key}</Key>\n    </Object>"
            for key in keys
        )
        xml_body = f'''<?xml version="1.0" encoding="UTF-8"?>
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
{objects_xml}
</Delete>'''

        body_bytes = xml_body.encode("utf-8")
        url = f"{endpoint_url}/{test_bucket}?delete"

        headers = {
            "Content-Type": "application/xml",
            "Content-MD5": calculate_content_md5(body_bytes),
            "Content-Length": str(len(body_bytes)),
            "x-amz-content-sha256": calculate_content_sha256(body_bytes),
        }

        signed_headers = sign_request(
            method="POST",
            url=url,
            headers=headers,
            body=body_bytes,
            credentials=credentials,
            region=region,
        )

        response = requests.post(url, data=body_bytes, headers=signed_headers, verify=False)

        json_metadata["status_code"] = response.status_code

        # Should be rejected - exceeds 1000 object limit
        if response.status_code == 400:
            json_metadata["behavior"] = "correctly_rejected"
        elif response.status_code == 200:
            json_metadata["behavior"] = "accepted_unexpectedly"

        # AWS S3 should reject this
        assert response.status_code == 400, (
            f"Expected 400 for >1000 objects, got {response.status_code}"
        )

    @pytest.mark.edge_case
    def test_unicode_key(
        self,
        s3_client,
        test_bucket,
        endpoint_url,
        credentials,
        region,
        json_metadata,
    ):
        """Test DeleteObjects with Unicode characters in key."""
        test_id = uuid.uuid4().hex[:8]
        key_name = f"test-unicode-\u4e2d\u6587-\u65e5\u672c\u8a9e-\u00e9\u00e8-{test_id}"

        json_metadata["key"] = key_name

        # Create object
        try:
            s3_client.put_object(
                Bucket=test_bucket, Key=key_name, Body=b"test content"
            )
            json_metadata["object_created"] = True
        except Exception as e:
            json_metadata["object_created"] = False
            json_metadata["create_error"] = str(e)

        # Make delete request
        response = self._make_delete_request(
            test_bucket, [key_name], endpoint_url, credentials, region
        )

        json_metadata["status_code"] = response.status_code

        # Cleanup
        try:
            s3_client.delete_object(Bucket=test_bucket, Key=key_name)
        except Exception:
            pass

        # Should succeed
        assert response.status_code == 200
