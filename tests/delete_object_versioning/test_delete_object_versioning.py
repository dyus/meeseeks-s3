"""DeleteObject versioning tests.

Tests DeleteObject behavior across versioning states:
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
    resp = make_request("PUT", f"/{bucket}", body=body,
                       headers={"Content-Type": "application/xml"}, query_params="?versioning")
    sc = _sc(resp)
    assert sc == 200, f"PutBucketVersioning({status}) failed: {sc}"


def _put_object(make_request, bucket, key, body_bytes):
    resp = make_request("PUT", f"/{bucket}/{key}", body=body_bytes)
    sc = _sc(resp)
    assert sc == 200, f"PutObject failed: {sc}"
    return resp


def _get_object(make_request, bucket, key, version_id=None):
    qp = f"?versionId={version_id}" if version_id else ""
    return make_request("GET", f"/{bucket}/{key}", query_params=qp)


def _delete_object(make_request, bucket, key, version_id=None):
    qp = f"?versionId={version_id}" if version_id else ""
    return make_request("DELETE", f"/{bucket}/{key}", query_params=qp)


def _sc(resp):
    return resp.aws.status_code if hasattr(resp, "comparison") else resp.status_code


def _h(resp):
    """CaseInsensitiveDict headers."""
    return resp.aws.headers if hasattr(resp, "comparison") else resp.headers


def _text(resp):
    return resp.aws.text if hasattr(resp, "comparison") else resp.text


def _body(resp):
    return resp.aws.content if hasattr(resp, "comparison") else resp.content


def _vid(resp):
    return _h(resp).get("x-amz-version-id")


def _unique_key(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# ===========================================================================
# 1. Versioning Disabled (Suspended as proxy)
# ===========================================================================

@pytest.mark.s3_handler("DeleteObject")
class TestDeleteObjectVersioningDisabled:
    """DeleteObject when versioning is disabled/suspended."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_1_1_delete_existing_object(self, test_bucket, make_request, json_metadata):
        """DELETE existing object → 204, object gone."""
        key = _unique_key("del-dis-1")
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"to-delete")

        resp = _delete_object(make_request, test_bucket, key)
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 204, f"Expected 204, got {status}: {_text(resp)[:200]}"

        # Object should be gone
        get_resp = _get_object(make_request, test_bucket, key)
        assert _sc(get_resp) == 404

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_1_2_delete_nonexistent_object(self, test_bucket, make_request, json_metadata):
        """DELETE nonexistent object → 204 (idempotent, no error)."""
        key = _unique_key("del-dis-2-nonexist")
        _put_versioning(make_request, test_bucket, "Suspended")

        resp = _delete_object(make_request, test_bucket, key)
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 204, f"Expected 204, got {status}: {_text(resp)[:200]}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_1_3_delete_no_version_id_header(self, test_bucket, make_request, json_metadata):
        """DELETE on disabled bucket → no x-amz-version-id header."""
        key = _unique_key("del-dis-3")
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"data")

        resp = _delete_object(make_request, test_bucket, key)
        vid = _vid(resp)
        json_metadata["version_id"] = vid
        # AWS does not return version-id on disabled bucket delete
        # (some implementations return None, some return nothing)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_1_4_double_delete(self, test_bucket, make_request, json_metadata):
        """DELETE twice → both return 204."""
        key = _unique_key("del-dis-4")
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"data")

        resp1 = _delete_object(make_request, test_bucket, key)
        resp2 = _delete_object(make_request, test_bucket, key)
        assert _sc(resp1) == 204
        assert _sc(resp2) == 204


# ===========================================================================
# 2. Versioning Enabled
# ===========================================================================

@pytest.mark.s3_handler("DeleteObject")
class TestDeleteObjectVersioningEnabled:
    """DeleteObject when versioning is enabled."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_1_delete_creates_delete_marker(self, test_bucket, make_request, json_metadata):
        """DELETE without versionId → 204, creates delete marker, returns vid + dm header."""
        key = _unique_key("del-en-1")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"versioned")

        resp = _delete_object(make_request, test_bucket, key)
        status = _sc(resp)
        vid = _vid(resp)
        dm = _h(resp).get("x-amz-delete-marker")

        json_metadata["status"] = status
        json_metadata["version_id"] = vid
        json_metadata["delete_marker"] = dm

        assert status == 204, f"Expected 204, got {status}"
        assert vid is not None and vid != "", f"Expected version-id (DM id), got: {vid!r}"
        assert dm == "true", f"Expected x-amz-delete-marker: true, got: {dm!r}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_2_get_after_delete_returns_404(self, test_bucket, make_request, json_metadata):
        """After DELETE (DM created), GET without versionId → 404 NoSuchKey."""
        key = _unique_key("del-en-2")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"versioned")

        _delete_object(make_request, test_bucket, key)

        get_resp = _get_object(make_request, test_bucket, key)
        status = _sc(get_resp)
        json_metadata["get_status"] = status
        assert status == 404, f"Expected 404, got {status}: {_text(get_resp)[:200]}"

        error_code, _ = extract_error_info(_text(get_resp))
        assert error_code == "NoSuchKey"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_3_old_version_survives_delete(self, test_bucket, make_request, json_metadata):
        """After DELETE, old version still accessible by versionId."""
        key = _unique_key("del-en-3")
        _put_versioning(make_request, test_bucket, "Enabled")
        put_resp = _put_object(make_request, test_bucket, key, b"original")
        v1_vid = _vid(put_resp)
        assert v1_vid, f"PutObject vid empty: {v1_vid!r}"

        _delete_object(make_request, test_bucket, key)

        get_resp = _get_object(make_request, test_bucket, key, version_id=v1_vid)
        assert _sc(get_resp) == 200
        assert _body(get_resp) == b"original"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_4_delete_specific_version(self, test_bucket, make_request, json_metadata):
        """DELETE ?versionId=X → 204, permanently removes that version."""
        key = _unique_key("del-en-4")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp_v1 = _put_object(make_request, test_bucket, key, b"v1")
        v1_vid = _vid(resp_v1)
        _put_object(make_request, test_bucket, key, b"v2")

        assert v1_vid, f"v1 vid empty"

        # Delete specific version
        del_resp = _delete_object(make_request, test_bucket, key, version_id=v1_vid)
        status = _sc(del_resp)
        json_metadata["delete_status"] = status
        assert status == 204

        # v1 should be gone
        get_resp = _get_object(make_request, test_bucket, key, version_id=v1_vid)
        assert _sc(get_resp) == 404

        # v2 (latest) should still be accessible
        get_latest = _get_object(make_request, test_bucket, key)
        assert _sc(get_latest) == 200
        assert _body(get_latest) == b"v2"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_5_delete_specific_version_no_dm(self, test_bucket, make_request, json_metadata):
        """DELETE ?versionId=X does NOT create delete marker, no dm header."""
        key = _unique_key("del-en-5")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp_v1 = _put_object(make_request, test_bucket, key, b"v1")
        v1_vid = _vid(resp_v1)

        del_resp = _delete_object(make_request, test_bucket, key, version_id=v1_vid)
        dm = _h(del_resp).get("x-amz-delete-marker")
        json_metadata["delete_marker"] = dm
        # DELETE with versionId does NOT set x-amz-delete-marker
        assert dm is None, f"Expected no delete-marker header, got: {dm!r}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_6_delete_delete_marker_by_version_id(self, test_bucket, make_request, json_metadata):
        """DELETE ?versionId=<dm-id> → 204, removes delete marker, object revived."""
        key = _unique_key("del-en-6")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"original")

        # Create DM
        del_resp = _delete_object(make_request, test_bucket, key)
        dm_vid = _vid(del_resp)
        assert dm_vid, f"DM vid empty"

        # Verify object is "deleted"
        get_resp = _get_object(make_request, test_bucket, key)
        assert _sc(get_resp) == 404

        # Delete the DM itself
        del_dm_resp = _delete_object(make_request, test_bucket, key, version_id=dm_vid)
        status = _sc(del_dm_resp)
        dm_header = _h(del_dm_resp).get("x-amz-delete-marker")
        json_metadata["del_dm_status"] = status
        json_metadata["del_dm_marker"] = dm_header

        assert status == 204
        # Deleting a DM returns x-amz-delete-marker: true
        assert dm_header == "true", f"Expected delete-marker: true when deleting DM, got: {dm_header!r}"

        # Object should be accessible again
        get_resp2 = _get_object(make_request, test_bucket, key)
        assert _sc(get_resp2) == 200
        assert _body(get_resp2) == b"original"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_7_delete_nonexistent_creates_dm(self, test_bucket, make_request, json_metadata):
        """DELETE nonexistent key on versioned bucket → 204, creates orphan DM."""
        key = _unique_key("del-en-7-nonexist")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp = _delete_object(make_request, test_bucket, key)
        status = _sc(resp)
        vid = _vid(resp)
        dm = _h(resp).get("x-amz-delete-marker")

        json_metadata["status"] = status
        json_metadata["version_id"] = vid
        json_metadata["delete_marker"] = dm

        assert status == 204
        assert vid is not None and vid != "", f"Expected DM version-id, got: {vid!r}"
        assert dm == "true"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_8_delete_invalid_version_id(self, test_bucket, make_request, json_metadata):
        """DELETE ?versionId=invalid-format → 400 InvalidArgument."""
        key = _unique_key("del-en-8")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")

        resp = _delete_object(make_request, test_bucket, key, version_id="9999999999999999")
        status = _sc(resp)
        json_metadata["status"] = status
        assert status == 400, f"Expected 400, got {status}: {_text(resp)[:200]}"
        error_code, _ = extract_error_info(_text(resp))
        assert error_code == "InvalidArgument"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_2_9_multiple_delete_markers(self, test_bucket, make_request, json_metadata):
        """Multiple DELETEs → multiple DMs with different version-ids."""
        key = _unique_key("del-en-9")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")

        del1 = _delete_object(make_request, test_bucket, key)
        dm1_vid = _vid(del1)

        del2 = _delete_object(make_request, test_bucket, key)
        dm2_vid = _vid(del2)

        json_metadata["dm1_vid"] = dm1_vid
        json_metadata["dm2_vid"] = dm2_vid

        assert dm1_vid and dm2_vid, f"DM vids empty: {dm1_vid!r}, {dm2_vid!r}"
        assert dm1_vid != dm2_vid, f"DM vids should be different: {dm1_vid} == {dm2_vid}"


# ===========================================================================
# 3. Versioning Suspended
# ===========================================================================

@pytest.mark.s3_handler("DeleteObject")
class TestDeleteObjectVersioningSuspended:
    """DeleteObject when versioning is suspended."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_3_1_delete_creates_null_dm(self, test_bucket, make_request, json_metadata):
        """DELETE on suspended → 204, creates null delete marker."""
        key = _unique_key("del-sus-1")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")
        _put_versioning(make_request, test_bucket, "Suspended")

        resp = _delete_object(make_request, test_bucket, key)
        status = _sc(resp)
        vid = _vid(resp)
        dm = _h(resp).get("x-amz-delete-marker")

        json_metadata["status"] = status
        json_metadata["version_id"] = vid
        json_metadata["delete_marker"] = dm

        assert status == 204
        assert dm == "true", f"Expected x-amz-delete-marker: true, got: {dm!r}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_3_2_old_versions_survive_suspended_delete(self, test_bucket, make_request, json_metadata):
        """Old versioned objects survive DELETE when suspended."""
        key = _unique_key("del-sus-2")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp_v1 = _put_object(make_request, test_bucket, key, b"v1-enabled")
        v1_vid = _vid(resp_v1)
        assert v1_vid, f"v1 vid empty"

        _put_versioning(make_request, test_bucket, "Suspended")
        _delete_object(make_request, test_bucket, key)

        # Old version still accessible by versionId
        get_resp = _get_object(make_request, test_bucket, key, version_id=v1_vid)
        assert _sc(get_resp) == 200
        assert _body(get_resp) == b"v1-enabled"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_3_3_delete_specific_version_while_suspended(self, test_bucket, make_request, json_metadata):
        """DELETE ?versionId=X while suspended → 204, removes that version."""
        key = _unique_key("del-sus-3")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp_v1 = _put_object(make_request, test_bucket, key, b"v1")
        v1_vid = _vid(resp_v1)
        assert v1_vid

        _put_versioning(make_request, test_bucket, "Suspended")

        del_resp = _delete_object(make_request, test_bucket, key, version_id=v1_vid)
        assert _sc(del_resp) == 204

        # v1 gone
        get_resp = _get_object(make_request, test_bucket, key, version_id=v1_vid)
        assert _sc(get_resp) == 404

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_3_4_suspended_delete_replaces_null_version(self, test_bucket, make_request, json_metadata):
        """DELETE on suspended overwrites null version with null DM."""
        key = _unique_key("del-sus-4")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"versioned")
        _put_versioning(make_request, test_bucket, "Suspended")

        # PUT creates null version
        _put_object(make_request, test_bucket, key, b"null-version")

        # DELETE replaces null version with null DM
        del_resp = _delete_object(make_request, test_bucket, key)
        assert _sc(del_resp) == 204

        # GET latest → 404 (null DM)
        get_resp = _get_object(make_request, test_bucket, key)
        assert _sc(get_resp) == 404

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_3_5_get_latest_after_suspended_delete_returns_dm_headers(self, test_bucket, make_request, json_metadata):
        """GET after suspended DELETE → 404 with delete-marker headers."""
        key = _unique_key("del-sus-5")
        _put_versioning(make_request, test_bucket, "Enabled")
        _put_object(make_request, test_bucket, key, b"data")
        _put_versioning(make_request, test_bucket, "Suspended")

        _delete_object(make_request, test_bucket, key)

        get_resp = _get_object(make_request, test_bucket, key)
        status = _sc(get_resp)
        headers = _h(get_resp)

        json_metadata["get_status"] = status
        json_metadata["delete_marker"] = headers.get("x-amz-delete-marker")
        json_metadata["version_id"] = headers.get("x-amz-version-id")

        assert status == 404
        assert headers.get("x-amz-delete-marker") == "true"
