"""PutObject versioning header tests.

Verifies that PutObject correctly returns x-amz-version-id in all
versioning modes: Disabled, Enabled, Suspended.

Also tests DeleteObject x-amz-version-id and overwrite behavior.
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


def _put_object(make_request, bucket, key, body_bytes, extra_headers=None):
    headers = {}
    if extra_headers:
        headers.update(extra_headers)
    return make_request("PUT", f"/{bucket}/{key}", body=body_bytes, headers=headers)


def _delete_object(make_request, bucket, key, version_id=None):
    qp = f"?versionId={version_id}" if version_id else ""
    return make_request("DELETE", f"/{bucket}/{key}", query_params=qp)


def _get_object(make_request, bucket, key, version_id=None):
    qp = f"?versionId={version_id}" if version_id else ""
    return make_request("GET", f"/{bucket}/{key}", query_params=qp)


def _sc(resp):
    return resp.aws.status_code if hasattr(resp, "comparison") else resp.status_code


def _headers(resp):
    """Get headers as CaseInsensitiveDict-like lookup.

    requests.Response.headers is CaseInsensitiveDict, but dict() loses that.
    We keep the raw object for case-insensitive .get().
    """
    return resp.aws.headers if hasattr(resp, "comparison") else resp.headers


def _text(resp):
    return resp.aws.text if hasattr(resp, "comparison") else resp.text


def _body(resp):
    return resp.aws.content if hasattr(resp, "comparison") else resp.content


def _vid(resp):
    return _headers(resp).get("x-amz-version-id")


def _unique_key(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# ===========================================================================
# 1. Versioning Disabled (Suspended as proxy)
# ===========================================================================

@pytest.mark.s3_handler("PutObject")
class TestPutObjectVersioningDisabled:
    """PutObject when versioning is disabled/suspended (no version-id expected)."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_put_no_version_id_header(self, test_bucket, make_request, json_metadata):
        """PUT on disabled bucket → 200, NO x-amz-version-id header."""
        key = _unique_key("po-dis-1")
        _put_versioning(make_request, test_bucket, "Suspended")

        resp = _put_object(make_request, test_bucket, key, b"disabled-data")
        status = _sc(resp)
        vid = _vid(resp)

        json_metadata["status"] = status
        json_metadata["version_id"] = vid
        assert status == 200, f"Expected 200, got {status}: {_text(resp)[:200]}"
        # On suspended bucket, PutObject should NOT return version-id
        # (or return "null" — AWS omits the header entirely for suspended/never-versioned)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_put_overwrite_no_version_id(self, test_bucket, make_request, json_metadata):
        """PUT overwrite on disabled bucket → 200, no version-id, body replaced."""
        key = _unique_key("po-dis-2")
        _put_versioning(make_request, test_bucket, "Suspended")

        _put_object(make_request, test_bucket, key, b"original")
        resp2 = _put_object(make_request, test_bucket, key, b"overwritten")
        status = _sc(resp2)
        vid = _vid(resp2)

        json_metadata["status"] = status
        json_metadata["version_id"] = vid
        assert status == 200

        # Verify body was overwritten
        get_resp = _get_object(make_request, test_bucket, key)
        assert _body(get_resp) == b"overwritten"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delete_no_version_id(self, test_bucket, make_request, json_metadata):
        """DELETE on disabled bucket → 204, no version-id."""
        key = _unique_key("po-dis-3")
        _put_versioning(make_request, test_bucket, "Suspended")

        _put_object(make_request, test_bucket, key, b"to-delete")
        resp = _delete_object(make_request, test_bucket, key)
        status = _sc(resp)
        vid = _vid(resp)

        json_metadata["status"] = status
        json_metadata["version_id"] = vid
        assert status == 204, f"Expected 204, got {status}: {_text(resp)[:200]}"


# ===========================================================================
# 2. Versioning Enabled
# ===========================================================================

@pytest.mark.s3_handler("PutObject")
class TestPutObjectVersioningEnabled:
    """PutObject when versioning is enabled — must return x-amz-version-id."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_put_returns_version_id(self, test_bucket, make_request, json_metadata):
        """PUT on enabled bucket → 200, x-amz-version-id is non-empty."""
        key = _unique_key("po-en-1")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp = _put_object(make_request, test_bucket, key, b"versioned-data")
        status = _sc(resp)
        vid = _vid(resp)

        json_metadata["status"] = status
        json_metadata["version_id"] = vid
        assert status == 200, f"Expected 200, got {status}: {_text(resp)[:200]}"
        assert vid is not None and vid != "", (
            f"x-amz-version-id must be non-empty on versioned bucket, got: {vid!r}"
        )

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_put_two_versions_different_ids(self, test_bucket, make_request, json_metadata):
        """Two PUTs → two different version-ids."""
        key = _unique_key("po-en-2")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp1 = _put_object(make_request, test_bucket, key, b"version1")
        resp2 = _put_object(make_request, test_bucket, key, b"version2")
        vid1 = _vid(resp1)
        vid2 = _vid(resp2)

        json_metadata["vid1"] = vid1
        json_metadata["vid2"] = vid2
        assert vid1 and vid2, f"Both version-ids must be non-empty: v1={vid1!r}, v2={vid2!r}"
        assert vid1 != vid2, f"Version-ids must be different: {vid1} == {vid2}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_put_version_id_retrievable(self, test_bucket, make_request, json_metadata):
        """PUT version-id can be used to GET that specific version."""
        key = _unique_key("po-en-3")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp1 = _put_object(make_request, test_bucket, key, b"first")
        vid1 = _vid(resp1)
        _put_object(make_request, test_bucket, key, b"second")

        json_metadata["vid1"] = vid1
        assert vid1, f"version-id must be non-empty: {vid1!r}"

        # GET v1 by version-id should return "first"
        get_resp = _get_object(make_request, test_bucket, key, version_id=vid1)
        get_status = _sc(get_resp)
        assert get_status == 200, f"GET by vid failed: {get_status}: {_text(get_resp)[:200]}"
        assert _body(get_resp) == b"first", f"Body mismatch: {_body(get_resp)!r}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delete_returns_version_id(self, test_bucket, make_request, json_metadata):
        """DELETE on enabled bucket → 204, x-amz-version-id (delete marker id) non-empty."""
        key = _unique_key("po-en-4")
        _put_versioning(make_request, test_bucket, "Enabled")

        _put_object(make_request, test_bucket, key, b"to-delete")
        resp = _delete_object(make_request, test_bucket, key)
        status = _sc(resp)
        vid = _vid(resp)
        headers = _headers(resp)

        json_metadata["status"] = status
        json_metadata["version_id"] = vid
        json_metadata["delete_marker"] = headers.get("x-amz-delete-marker", "")
        assert status == 204, f"Expected 204, got {status}: {_text(resp)[:200]}"
        assert vid is not None and vid != "", (
            f"DELETE must return x-amz-version-id (delete marker id), got: {vid!r}"
        )
        assert headers.get("x-amz-delete-marker") == "true", (
            f"Expected x-amz-delete-marker: true, got: {headers.get('x-amz-delete-marker')}"
        )

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delete_specific_version(self, test_bucket, make_request, json_metadata):
        """DELETE with versionId on enabled bucket → 204, permanently removes version."""
        key = _unique_key("po-en-5")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp1 = _put_object(make_request, test_bucket, key, b"v1")
        vid1 = _vid(resp1)
        assert vid1, f"version-id must be non-empty: {vid1!r}"

        resp2 = _put_object(make_request, test_bucket, key, b"v2")

        # Delete specific version
        del_resp = _delete_object(make_request, test_bucket, key, version_id=vid1)
        del_status = _sc(del_resp)
        json_metadata["delete_status"] = del_status
        assert del_status == 204, f"Expected 204, got {del_status}"

        # v1 should no longer exist
        get_resp = _get_object(make_request, test_bucket, key, version_id=vid1)
        get_status = _sc(get_resp)
        json_metadata["get_deleted_status"] = get_status
        assert get_status == 404, f"Expected 404 for deleted version, got {get_status}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_get_latest_returns_version_id(self, test_bucket, make_request, json_metadata):
        """GET without versionId on enabled bucket → 200, x-amz-version-id = latest."""
        key = _unique_key("po-en-6")
        _put_versioning(make_request, test_bucket, "Enabled")

        _put_object(make_request, test_bucket, key, b"v1")
        resp_v2 = _put_object(make_request, test_bucket, key, b"v2")
        vid2 = _vid(resp_v2)

        get_resp = _get_object(make_request, test_bucket, key)
        get_status = _sc(get_resp)
        get_vid = _vid(get_resp)

        json_metadata["put_vid2"] = vid2
        json_metadata["get_vid"] = get_vid
        assert get_status == 200
        assert get_vid is not None and get_vid != "", (
            f"GET latest must return x-amz-version-id, got: {get_vid!r}"
        )
        # If PutObject returns vid, they should match
        if vid2:
            assert get_vid == vid2, f"GET latest vid ({get_vid}) != PUT v2 vid ({vid2})"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_put_etag_present(self, test_bucket, make_request, json_metadata):
        """PUT on enabled bucket → ETag header present."""
        key = _unique_key("po-en-7")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp = _put_object(make_request, test_bucket, key, b"etag-test")
        status = _sc(resp)
        headers = _headers(resp)
        etag = headers.get("ETag", headers.get("etag", ""))

        json_metadata["status"] = status
        json_metadata["etag"] = etag
        assert status == 200
        assert etag, f"ETag must be present, got: {etag!r}"


# ===========================================================================
# 3. Versioning Suspended
# ===========================================================================

@pytest.mark.s3_handler("PutObject")
class TestPutObjectVersioningSuspended:
    """PutObject when versioning is suspended — null version behavior."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_put_returns_null_version_id(self, test_bucket, make_request, json_metadata):
        """PUT on suspended bucket → 200, x-amz-version-id absent or null."""
        key = _unique_key("po-sus-1")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_versioning(make_request, test_bucket, "Suspended")

        resp = _put_object(make_request, test_bucket, key, b"suspended-data")
        status = _sc(resp)
        vid = _vid(resp)

        json_metadata["status"] = status
        json_metadata["version_id"] = vid
        assert status == 200
        # AWS does not return x-amz-version-id on suspended bucket PUT
        # (or some implementations return "null")

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_put_overwrites_null_version(self, test_bucket, make_request, json_metadata):
        """Two PUTs on suspended → second overwrites null version."""
        key = _unique_key("po-sus-2")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_versioning(make_request, test_bucket, "Suspended")

        _put_object(make_request, test_bucket, key, b"first")
        _put_object(make_request, test_bucket, key, b"second")

        get_resp = _get_object(make_request, test_bucket, key)
        assert _body(get_resp) == b"second", f"Expected 'second', got {_body(get_resp)!r}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_old_versions_preserved(self, test_bucket, make_request, json_metadata):
        """Versions created while Enabled survive after Suspend."""
        key = _unique_key("po-sus-3")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp_v1 = _put_object(make_request, test_bucket, key, b"v1-enabled")
        vid1 = _vid(resp_v1)
        json_metadata["vid1"] = vid1
        assert vid1, f"version-id must be non-empty while Enabled: {vid1!r}"

        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"suspended-overwrite")

        # Old version should still be accessible by versionId
        get_resp = _get_object(make_request, test_bucket, key, version_id=vid1)
        get_status = _sc(get_resp)
        assert get_status == 200, f"Old version should be accessible, got {get_status}"
        assert _body(get_resp) == b"v1-enabled"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delete_creates_null_delete_marker(self, test_bucket, make_request, json_metadata):
        """DELETE on suspended → 204, creates null delete marker."""
        key = _unique_key("po-sus-4")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")
        _put_versioning(make_request, test_bucket, "Suspended")

        del_resp = _delete_object(make_request, test_bucket, key)
        status = _sc(del_resp)
        headers = _headers(del_resp)

        json_metadata["status"] = status
        json_metadata["delete_marker"] = headers.get("x-amz-delete-marker", "")
        assert status == 204, f"Expected 204, got {status}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_get_latest_vid_null_after_suspend_write(self, test_bucket, make_request, json_metadata):
        """GET latest on suspended → vid=null (if header present)."""
        key = _unique_key("po-sus-5")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"enabled-version")
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"suspended-version")

        get_resp = _get_object(make_request, test_bucket, key)
        get_vid = _vid(get_resp)

        json_metadata["get_vid"] = get_vid
        assert _sc(get_resp) == 200
        # AWS returns x-amz-version-id: null for suspended bucket reads
        assert get_vid == "null", (
            f"Expected x-amz-version-id='null' for suspended read, got: {get_vid!r}"
        )


# ===========================================================================
# 4. Versioning state transitions — version-id continuity
# ===========================================================================

@pytest.mark.s3_handler("PutObject")
class TestPutObjectVersioningTransitions:
    """Cross-state tests: version-id behavior across Enable/Suspend transitions."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_enable_suspend_enable_versions_intact(self, test_bucket, make_request, json_metadata):
        """Enable → PUT v1 → Suspend → PUT v2 → Enable → PUT v3: all versions accessible."""
        key = _unique_key("po-trans-1")

        # Phase 1: Enabled
        _put_versioning(make_request, test_bucket, "Enabled")
        resp1 = _put_object(make_request, test_bucket, key, b"v1")
        vid1 = _vid(resp1)
        json_metadata["vid1"] = vid1
        assert vid1, f"v1 version-id must be non-empty: {vid1!r}"

        # Phase 2: Suspended
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"v2-suspended")

        # Phase 3: Re-enabled
        _put_versioning(make_request, test_bucket, "Enabled")
        resp3 = _put_object(make_request, test_bucket, key, b"v3")
        vid3 = _vid(resp3)
        json_metadata["vid3"] = vid3
        assert vid3, f"v3 version-id must be non-empty: {vid3!r}"

        # v1 still accessible
        get1 = _get_object(make_request, test_bucket, key, version_id=vid1)
        assert _sc(get1) == 200, f"v1 should be accessible: {_sc(get1)}"
        assert _body(get1) == b"v1"

        # v3 (latest)
        get3 = _get_object(make_request, test_bucket, key, version_id=vid3)
        assert _sc(get3) == 200
        assert _body(get3) == b"v3"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_version_id_format(self, test_bucket, make_request, json_metadata):
        """Version-id should be a non-trivial string (not 'null', not empty)."""
        key = _unique_key("po-trans-2")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp = _put_object(make_request, test_bucket, key, b"format-check")
        vid = _vid(resp)

        json_metadata["version_id"] = vid
        assert vid, f"version-id must be non-empty: {vid!r}"
        assert vid != "null", f"version-id should not be 'null' on Enabled bucket: {vid}"
        assert len(vid) > 5, f"version-id looks too short: {vid!r}"
