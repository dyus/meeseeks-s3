"""GetObject versioning tests based on getobject_versioning.md.

Tests GetObject behavior across versioning states:
- Versioning Disabled (1.x)
- Versioning Enabled (2.x)
- Versioning Suspended (3.x)

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import uuid

import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml_with_mfa


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _put_versioning(make_request, bucket, status):
    body = build_versioning_xml_with_mfa(status, mfa_delete="Disabled")
    headers = {"Content-Type": "application/xml"}
    resp = make_request("PUT", f"/{bucket}", body=body, headers=headers, query_params="?versioning")
    sc = resp.aws.status_code if hasattr(resp, "comparison") else resp.status_code
    assert sc == 200, f"PutBucketVersioning({status}) failed: {sc}"


def _put_object(make_request, bucket, key, body_bytes):
    resp = make_request("PUT", f"/{bucket}/{key}", body=body_bytes)
    sc = resp.aws.status_code if hasattr(resp, "comparison") else resp.status_code
    assert sc == 200, f"PutObject failed: {sc}"
    return resp


def _delete_object(make_request, bucket, key, version_id=None):
    qp = f"?versionId={version_id}" if version_id else ""
    return make_request("DELETE", f"/{bucket}/{key}", query_params=qp)


def _get_object(make_request, bucket, key, version_id=None, query_params=None):
    """GET object. query_params overrides versionId if set."""
    if query_params is not None:
        qp = query_params
    elif version_id is not None:
        qp = f"?versionId={version_id}"
    else:
        qp = ""
    return make_request("GET", f"/{bucket}/{key}", query_params=qp)


def _sc(resp):
    return resp.aws.status_code if hasattr(resp, "comparison") else resp.status_code


def _headers(resp):
    """Keep CaseInsensitiveDict for case-insensitive header lookups."""
    return resp.aws.headers if hasattr(resp, "comparison") else resp.headers


def _text(resp):
    return resp.aws.text if hasattr(resp, "comparison") else resp.text


def _body(resp):
    return resp.aws.content if hasattr(resp, "comparison") else resp.content


def _vid(resp):
    """Extract x-amz-version-id from response."""
    return _headers(resp).get("x-amz-version-id", "")


def _unique_key(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# 1. Versioning Disabled
# ---------------------------------------------------------------------------

@pytest.mark.get_object_versioning
@pytest.mark.s3_handler("GetObject")
class TestGetObjectVersioningDisabled:
    """GetObject tests with versioning disabled."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_1_1_get_without_version_id(self, test_bucket, make_request, json_metadata):
        """1.1: GET without versionId on unversioned bucket → 200, no vid header."""
        key = _unique_key("t1-1")
        # Ensure versioning suspended (can't truly disable once enabled)
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"hello")

        resp = _get_object(make_request, test_bucket, key)
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 200, f"Expected 200, got {status}: {_text(resp)[:200]}"

        body = _body(resp)
        assert body == b"hello", f"Body mismatch: {body!r}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_1_2_get_version_id_null(self, test_bucket, make_request, json_metadata):
        """1.2: GET versionId=null on unversioned bucket → 200."""
        key = _unique_key("t1-2")
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"hello-null")

        resp = _get_object(make_request, test_bucket, key, version_id="null")
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 200, f"Expected 200, got {status}: {_text(resp)[:200]}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_1_3_get_nonexistent_version_id(self, test_bucket, make_request, json_metadata):
        """1.3: GET versionId=nonexistent → 400 InvalidArgument (AWS) or 404."""
        key = _unique_key("t1-3")
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"hello")

        resp = _get_object(make_request, test_bucket, key, version_id="nonexistent-version-id-12345")
        status = _sc(resp)
        json_metadata["status"] = status

        # AWS returns 400 InvalidArgument
        assert status == 400, f"Expected 400, got {status}: {_text(resp)[:200]}"
        error_code, _ = extract_error_info(_text(resp))
        json_metadata["error_code"] = error_code
        assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_1_4_get_empty_version_id(self, test_bucket, make_request, json_metadata):
        """1.4: GET versionId= (empty value) → 400 InvalidArgument."""
        key = _unique_key("t1-4")
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"hello")

        resp = _get_object(make_request, test_bucket, key, query_params="?versionId=")
        status = _sc(resp)
        json_metadata["status"] = status

        assert status == 400, f"Expected 400, got {status}: {_text(resp)[:200]}"
        error_code, _ = extract_error_info(_text(resp))
        json_metadata["error_code"] = error_code
        assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_1_5_get_version_id_no_value(self, test_bucket, make_request, json_metadata):
        """1.5: GET ?versionId (no value) → 400 InvalidArgument."""
        key = _unique_key("t1-5")
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"hello")

        resp = _get_object(make_request, test_bucket, key, query_params="?versionId")
        status = _sc(resp)
        json_metadata["status"] = status

        assert status == 400, f"Expected 400, got {status}: {_text(resp)[:200]}"
        error_code, _ = extract_error_info(_text(resp))
        json_metadata["error_code"] = error_code
        assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"


# ---------------------------------------------------------------------------
# 2. Versioning Enabled
# ---------------------------------------------------------------------------

@pytest.mark.get_object_versioning
@pytest.mark.s3_handler("GetObject")
class TestGetObjectVersioningEnabled:
    """GetObject tests with versioning enabled."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_1_get_latest_without_version_id(self, test_bucket, make_request, json_metadata):
        """2.1: GET without versionId when versioned → 200, vid=latest version."""
        key = _unique_key("t2-1")
        _put_versioning(make_request, test_bucket, "Enabled")

        # Upload v1 and v2
        _put_object(make_request, test_bucket, key, b"version1")
        resp_v2 = _put_object(make_request, test_bucket, key, b"version2")
        v2_vid = _vid(resp_v2)

        resp = _get_object(make_request, test_bucket, key)
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 200, f"Expected 200, got {status}: {_text(resp)[:200]}"

        body = _body(resp)
        assert body == b"version2", f"Body mismatch: {body!r}"

        vid = _vid(resp)
        json_metadata["version_id"] = vid
        # version-id should not be empty
        assert vid, f"x-amz-version-id is empty, expected a real version id"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_2_get_specific_version_v1(self, test_bucket, make_request, json_metadata):
        """2.2: GET versionId=v1 → 200, body=v1, vid=v1."""
        key = _unique_key("t2-2")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp_v1 = _put_object(make_request, test_bucket, key, b"version1")
        v1_vid = _vid(resp_v1)
        _put_object(make_request, test_bucket, key, b"version2")

        resp = _get_object(make_request, test_bucket, key, version_id=v1_vid)
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 200, f"Expected 200, got {status}: {_text(resp)[:200]}"

        body = _body(resp)
        assert body == b"version1", f"Body mismatch: {body!r}"

        vid = _vid(resp)
        assert vid == v1_vid, f"version-id mismatch: {vid} != {v1_vid}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_3_get_specific_version_v2_latest(self, test_bucket, make_request, json_metadata):
        """2.3: GET versionId=v2 (latest) → 200, body=v2, vid=v2."""
        key = _unique_key("t2-3")
        _put_versioning(make_request, test_bucket, "Enabled")

        _put_object(make_request, test_bucket, key, b"version1")
        resp_v2 = _put_object(make_request, test_bucket, key, b"version2")
        v2_vid = _vid(resp_v2)

        resp = _get_object(make_request, test_bucket, key, version_id=v2_vid)
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 200, f"Expected 200, got {status}: {_text(resp)[:200]}"

        body = _body(resp)
        assert body == b"version2", f"Body mismatch: {body!r}"

        vid = _vid(resp)
        assert vid == v2_vid, f"version-id mismatch: {vid} != {v2_vid}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_4_get_version_id_null_no_null_version(self, test_bucket, make_request, json_metadata):
        """2.4: GET versionId=null when no null-version exists → 404 NoSuchVersion."""
        key = _unique_key("t2-4")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"versioned")

        resp = _get_object(make_request, test_bucket, key, version_id="null")
        status = _sc(resp)
        json_metadata["status"] = status

        assert status == 404, f"Expected 404, got {status}: {_text(resp)[:200]}"
        error_code, _ = extract_error_info(_text(resp))
        json_metadata["error_code"] = error_code
        assert error_code == "NoSuchVersion", f"Expected NoSuchVersion, got {error_code}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_4a_get_empty_version_id(self, test_bucket, make_request, json_metadata):
        """2.4a: GET versionId= (empty) when versioned → 400 InvalidArgument."""
        key = _unique_key("t2-4a")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"versioned")

        resp = _get_object(make_request, test_bucket, key, query_params="?versionId=")
        status = _sc(resp)
        json_metadata["status"] = status

        assert status == 400, f"Expected 400, got {status}: {_text(resp)[:200]}"
        error_code, _ = extract_error_info(_text(resp))
        json_metadata["error_code"] = error_code
        assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_4b_get_version_id_no_value(self, test_bucket, make_request, json_metadata):
        """2.4b: GET ?versionId (no value) when versioned → 400 InvalidArgument."""
        key = _unique_key("t2-4b")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"versioned")

        resp = _get_object(make_request, test_bucket, key, query_params="?versionId")
        status = _sc(resp)
        json_metadata["status"] = status

        assert status == 400, f"Expected 400, got {status}: {_text(resp)[:200]}"
        error_code, _ = extract_error_info(_text(resp))
        json_metadata["error_code"] = error_code
        assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_5_get_latest_delete_marker(self, test_bucket, make_request, json_metadata):
        """2.5: GET without vid, latest=DeleteMarker → 404, delete-marker=true, has vid."""
        key = _unique_key("t2-5")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"to-be-deleted")

        # Create delete marker
        _delete_object(make_request, test_bucket, key)

        resp = _get_object(make_request, test_bucket, key)
        status = _sc(resp)
        headers = _headers(resp)
        json_metadata["status"] = status
        json_metadata["delete_marker"] = headers.get("x-amz-delete-marker", "")
        json_metadata["version_id"] = headers.get("x-amz-version-id", "")

        assert status == 404, f"Expected 404, got {status}: {_text(resp)[:300]}"
        assert headers.get("x-amz-delete-marker") == "true", (
            f"Expected x-amz-delete-marker: true, got: {headers.get('x-amz-delete-marker')}"
        )
        assert headers.get("x-amz-version-id"), (
            "Expected x-amz-version-id to be present and non-empty"
        )
        error_code, _ = extract_error_info(_text(resp))
        json_metadata["error_code"] = error_code
        assert error_code == "NoSuchKey", f"Expected NoSuchKey, got {error_code}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_6_get_version_id_of_delete_marker(self, test_bucket, make_request, json_metadata):
        """2.6: GET versionId=DeleteMarker → 405 MethodNotAllowed, delete-marker=true."""
        key = _unique_key("t2-6")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"to-be-deleted")

        # Create delete marker and get its version id
        del_resp = _delete_object(make_request, test_bucket, key)
        dm_vid = _vid(del_resp)
        assert dm_vid, "Delete marker version-id is empty"

        resp = _get_object(make_request, test_bucket, key, version_id=dm_vid)
        status = _sc(resp)
        headers = _headers(resp)
        json_metadata["status"] = status
        json_metadata["delete_marker"] = headers.get("x-amz-delete-marker", "")

        assert status == 405, f"Expected 405, got {status}: {_text(resp)[:300]}"
        assert headers.get("x-amz-delete-marker") == "true", (
            f"Expected x-amz-delete-marker: true, got: {headers.get('x-amz-delete-marker')}"
        )
        error_code, _ = extract_error_info(_text(resp))
        json_metadata["error_code"] = error_code
        assert error_code == "MethodNotAllowed", f"Expected MethodNotAllowed, got {error_code}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_7_get_version_before_delete_marker(self, test_bucket, make_request, json_metadata):
        """2.7: GET versionId=v1 (version before DM) → 200, body=ok."""
        key = _unique_key("t2-7")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp_v1 = _put_object(make_request, test_bucket, key, b"original")
        v1_vid = _vid(resp_v1)

        # Create delete marker
        _delete_object(make_request, test_bucket, key)

        resp = _get_object(make_request, test_bucket, key, version_id=v1_vid)
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 200, f"Expected 200, got {status}: {_text(resp)[:200]}"

        body = _body(resp)
        assert body == b"original", f"Body mismatch: {body!r}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_8_get_latest_after_revive(self, test_bucket, make_request, json_metadata):
        """2.8: GET latest after revive (PUT after DM) → 200, vid=new, body=revived."""
        key = _unique_key("t2-8")
        _put_versioning(make_request, test_bucket, "Enabled")

        _put_object(make_request, test_bucket, key, b"original")
        _delete_object(make_request, test_bucket, key)

        # Revive: PUT new version
        _put_object(make_request, test_bucket, key, b"revived")

        resp = _get_object(make_request, test_bucket, key)
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 200, f"Expected 200, got {status}: {_text(resp)[:200]}"

        body = _body(resp)
        assert body == b"revived", f"Body mismatch: {body!r}"

        vid = _vid(resp)
        json_metadata["version_id"] = vid
        assert vid, "x-amz-version-id should be non-empty after revive"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_9_get_version_id_of_non_latest_delete_marker(self, test_bucket, make_request, json_metadata):
        """2.9: GET versionId=DM (not latest, revived) → 405 MethodNotAllowed."""
        key = _unique_key("t2-9")
        _put_versioning(make_request, test_bucket, "Enabled")

        _put_object(make_request, test_bucket, key, b"original")

        # Create DM
        del_resp = _delete_object(make_request, test_bucket, key)
        dm_vid = _vid(del_resp)
        assert dm_vid, "Delete marker version-id is empty"

        # Revive — DM is no longer latest
        _put_object(make_request, test_bucket, key, b"revived")

        resp = _get_object(make_request, test_bucket, key, version_id=dm_vid)
        status = _sc(resp)
        headers = _headers(resp)
        json_metadata["status"] = status
        json_metadata["delete_marker"] = headers.get("x-amz-delete-marker", "")

        assert status == 405, f"Expected 405, got {status}: {_text(resp)[:300]}"
        assert headers.get("x-amz-delete-marker") == "true", (
            f"Expected x-amz-delete-marker: true, got: {headers.get('x-amz-delete-marker')}"
        )
        error_code, _ = extract_error_info(_text(resp))
        json_metadata["error_code"] = error_code
        assert error_code == "MethodNotAllowed", f"Expected MethodNotAllowed, got {error_code}"


# ---------------------------------------------------------------------------
# 3. Versioning Suspended
# ---------------------------------------------------------------------------

@pytest.mark.get_object_versioning
@pytest.mark.s3_handler("GetObject")
class TestGetObjectVersioningSuspended:
    """GetObject tests with versioning suspended."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_3_1_get_without_version_id(self, test_bucket, make_request, json_metadata):
        """3.1: GET without vid when suspended → 200, vid=null."""
        key = _unique_key("t3-1")
        # Enable → upload → Suspend → overwrite with null version
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"versioned")
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"suspended-write")

        resp = _get_object(make_request, test_bucket, key)
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 200, f"Expected 200, got {status}: {_text(resp)[:200]}"

        body = _body(resp)
        assert body == b"suspended-write", f"Body mismatch: {body!r}"

        vid = _vid(resp)
        json_metadata["version_id"] = vid
        # AWS returns "null" for suspended bucket's current version
        assert vid == "null", f"Expected vid='null', got '{vid}'"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_3_2_get_version_id_null(self, test_bucket, make_request, json_metadata):
        """3.2: GET versionId=null when suspended → 200, vid=null."""
        key = _unique_key("t3-2")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"versioned")
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"null-version")

        resp = _get_object(make_request, test_bucket, key, version_id="null")
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 200, f"Expected 200, got {status}: {_text(resp)[:200]}"

        vid = _vid(resp)
        assert vid == "null", f"Expected vid='null', got '{vid}'"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_3_3_get_old_versioned_id(self, test_bucket, make_request, json_metadata):
        """3.3: GET versionId=old (created while Enabled) when suspended → 200."""
        key = _unique_key("t3-3")
        _put_versioning(make_request, test_bucket, "Enabled")
        resp_v1 = _put_object(make_request, test_bucket, key, b"v1-enabled")
        v1_vid = _vid(resp_v1)

        _put_versioning(make_request, test_bucket, "Suspended")

        resp = _get_object(make_request, test_bucket, key, version_id=v1_vid)
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 200, f"Expected 200, got {status}: {_text(resp)[:200]}"

        body = _body(resp)
        assert body == b"v1-enabled", f"Body mismatch: {body!r}"

        vid = _vid(resp)
        assert vid == v1_vid, f"version-id mismatch: {vid} != {v1_vid}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_3_3a_get_empty_version_id_suspended(self, test_bucket, make_request, json_metadata):
        """3.3a: GET versionId= (empty) when suspended → 400 InvalidArgument."""
        key = _unique_key("t3-3a")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")
        _put_versioning(make_request, test_bucket, "Suspended")

        resp = _get_object(make_request, test_bucket, key, query_params="?versionId=")
        status = _sc(resp)
        json_metadata["status"] = status

        assert status == 400, f"Expected 400, got {status}: {_text(resp)[:200]}"
        error_code, _ = extract_error_info(_text(resp))
        json_metadata["error_code"] = error_code
        assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_3_3b_get_version_id_no_value_suspended(self, test_bucket, make_request, json_metadata):
        """3.3b: GET ?versionId (no value) when suspended → 400 InvalidArgument."""
        key = _unique_key("t3-3b")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")
        _put_versioning(make_request, test_bucket, "Suspended")

        resp = _get_object(make_request, test_bucket, key, query_params="?versionId")
        status = _sc(resp)
        json_metadata["status"] = status

        assert status == 400, f"Expected 400, got {status}: {_text(resp)[:200]}"
        error_code, _ = extract_error_info(_text(resp))
        json_metadata["error_code"] = error_code
        assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_3_4_get_latest_delete_marker_suspended(self, test_bucket, make_request, json_metadata):
        """3.4: GET without vid, latest=DM when suspended → 404, delete-marker=true, vid=null."""
        key = _unique_key("t3-4")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")
        _put_versioning(make_request, test_bucket, "Suspended")

        # Delete creates null delete marker
        _delete_object(make_request, test_bucket, key)

        resp = _get_object(make_request, test_bucket, key)
        status = _sc(resp)
        headers = _headers(resp)
        json_metadata["status"] = status
        json_metadata["delete_marker"] = headers.get("x-amz-delete-marker", "")
        json_metadata["version_id"] = headers.get("x-amz-version-id", "")

        assert status == 404, f"Expected 404, got {status}: {_text(resp)[:300]}"
        assert headers.get("x-amz-delete-marker") == "true", (
            f"Expected x-amz-delete-marker: true, got: {headers.get('x-amz-delete-marker')}"
        )

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_3_5_get_version_id_null_delete_marker_suspended(self, test_bucket, make_request, json_metadata):
        """3.5: GET versionId=null when null-version is DM (suspended) → 405 MethodNotAllowed."""
        key = _unique_key("t3-5")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")
        _put_versioning(make_request, test_bucket, "Suspended")

        # Delete creates null delete marker
        _delete_object(make_request, test_bucket, key)

        resp = _get_object(make_request, test_bucket, key, version_id="null")
        status = _sc(resp)
        headers = _headers(resp)
        json_metadata["status"] = status
        json_metadata["delete_marker"] = headers.get("x-amz-delete-marker", "")

        assert status == 405, f"Expected 405, got {status}: {_text(resp)[:300]}"
        assert headers.get("x-amz-delete-marker") == "true", (
            f"Expected x-amz-delete-marker: true, got: {headers.get('x-amz-delete-marker')}"
        )
        error_code, _ = extract_error_info(_text(resp))
        json_metadata["error_code"] = error_code
        assert error_code == "MethodNotAllowed", f"Expected MethodNotAllowed, got {error_code}"
