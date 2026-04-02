"""DeleteObject validation order tests.

Tests with "double errors" to determine the order in which AWS validates
parameters in DeleteObject. This helps understand where versionId validation
should be placed in the handler.

Each test combines an invalid versionId with another error condition.
The error that AWS returns first tells us the validation order.
"""

import uuid

import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml_with_mfa


def _put_versioning(make_request, bucket, status):
    body = build_versioning_xml_with_mfa(status, mfa_delete="Disabled")
    resp = make_request("PUT", f"/{bucket}", body=body,
                       headers={"Content-Type": "application/xml"}, query_params="?versioning")
    sc = resp.aws.status_code if hasattr(resp, "comparison") else resp.status_code
    assert sc == 200


def _put_object(make_request, bucket, key, body_bytes):
    resp = make_request("PUT", f"/{bucket}/{key}", body=body_bytes)
    sc = resp.aws.status_code if hasattr(resp, "comparison") else resp.status_code
    assert sc == 200
    return resp


def _sc(r):
    return r.aws.status_code if hasattr(r, "comparison") else r.status_code

def _h(r):
    return r.aws.headers if hasattr(r, "comparison") else r.headers

def _text(r):
    return r.aws.text if hasattr(r, "comparison") else r.text

def _unique_key(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.mark.s3_handler("DeleteObject")
class TestDeleteObjectValidationOrder:
    """Determine validation order by combining invalid versionId with other errors."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_vid_on_existing_object(self, test_bucket, make_request):
        """Invalid versionId + existing object → what error?
        Tests: is versionId validated before or after object lookup?"""
        key = _unique_key("val-1")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")

        resp = make_request("DELETE", f"/{test_bucket}/{key}",
                           query_params="?versionId=INVALID_FORMAT_12345")
        status = _sc(resp)
        error_code, error_msg = extract_error_info(_text(resp)) if status >= 400 else ("", "")

        print(f"\n--- Invalid versionId + existing object ---")
        print(f"  Status: {status}")
        print(f"  Error: {error_code}: {error_msg}")
        print(f"  Headers: x-amz-version-id={_h(resp).get('x-amz-version-id')}")

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_vid_on_nonexistent_object(self, test_bucket, make_request):
        """Invalid versionId + nonexistent object → what error?
        If InvalidArgument → versionId checked before object existence."""
        key = _unique_key("val-2-nonexist")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp = make_request("DELETE", f"/{test_bucket}/{key}",
                           query_params="?versionId=INVALID_FORMAT_12345")
        status = _sc(resp)
        error_code, error_msg = extract_error_info(_text(resp)) if status >= 400 else ("", "")

        print(f"\n--- Invalid versionId + nonexistent object ---")
        print(f"  Status: {status}")
        print(f"  Error: {error_code}: {error_msg}")

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_vid_on_nonexistent_bucket(self, test_bucket, make_request):
        """Invalid versionId + nonexistent bucket → what error?
        If NoSuchBucket → bucket checked before versionId.
        If InvalidArgument → versionId checked before bucket."""
        resp = make_request("DELETE", f"/nonexistent-bucket-{uuid.uuid4().hex[:8]}/somekey",
                           query_params="?versionId=INVALID_FORMAT_12345")
        status = _sc(resp)
        error_code, error_msg = extract_error_info(_text(resp)) if status >= 400 else ("", "")

        print(f"\n--- Invalid versionId + nonexistent bucket ---")
        print(f"  Status: {status}")
        print(f"  Error: {error_code}: {error_msg}")

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_vid_versioning_disabled(self, test_bucket, make_request):
        """Invalid versionId + versioning disabled → what error?"""
        key = _unique_key("val-4")
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"data")

        resp = make_request("DELETE", f"/{test_bucket}/{key}",
                           query_params="?versionId=INVALID_FORMAT_12345")
        status = _sc(resp)
        error_code, error_msg = extract_error_info(_text(resp)) if status >= 400 else ("", "")

        print(f"\n--- Invalid versionId + versioning disabled ---")
        print(f"  Status: {status}")
        print(f"  Error: {error_code}: {error_msg}")

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_vid_existing_object(self, test_bucket, make_request):
        """Empty versionId= + existing object → what error?"""
        key = _unique_key("val-5")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")

        resp = make_request("DELETE", f"/{test_bucket}/{key}",
                           query_params="?versionId=")
        status = _sc(resp)
        error_code, error_msg = extract_error_info(_text(resp)) if status >= 400 else ("", "")

        print(f"\n--- Empty versionId= + existing object ---")
        print(f"  Status: {status}")
        print(f"  Error: {error_code}: {error_msg}")
        print(f"  Headers: x-amz-delete-marker={_h(resp).get('x-amz-delete-marker')}")
        print(f"  Headers: x-amz-version-id={_h(resp).get('x-amz-version-id')}")

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_vid_no_value_existing_object(self, test_bucket, make_request):
        """?versionId (no value, no =) + existing object → what error?"""
        key = _unique_key("val-6")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")

        resp = make_request("DELETE", f"/{test_bucket}/{key}",
                           query_params="?versionId")
        status = _sc(resp)
        error_code, error_msg = extract_error_info(_text(resp)) if status >= 400 else ("", "")

        print(f"\n--- ?versionId (no value) + existing object ---")
        print(f"  Status: {status}")
        print(f"  Error: {error_code}: {error_msg}")
        print(f"  Headers: x-amz-delete-marker={_h(resp).get('x-amz-delete-marker')}")
        print(f"  Headers: x-amz-version-id={_h(resp).get('x-amz-version-id')}")

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_vid_null_string(self, test_bucket, make_request):
        """versionId=null on versioned bucket with existing object."""
        key = _unique_key("val-7")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")

        resp = make_request("DELETE", f"/{test_bucket}/{key}",
                           query_params="?versionId=null")
        status = _sc(resp)
        error_code, error_msg = extract_error_info(_text(resp)) if status >= 400 else ("", "")

        print(f"\n--- versionId=null + versioned object ---")
        print(f"  Status: {status}")
        print(f"  Error: {error_code}: {error_msg}")
        print(f"  Headers: x-amz-version-id={_h(resp).get('x-amz-version-id')}")
        print(f"  Headers: x-amz-delete-marker={_h(resp).get('x-amz-delete-marker')}")
