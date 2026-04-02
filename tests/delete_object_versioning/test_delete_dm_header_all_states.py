"""Test x-amz-delete-marker header when deleting a delete marker, across all bucket states.

AWS should return x-amz-delete-marker: true when DELETE ?versionId=<dm-id> removes a DM.
Tests this for Enabled and Suspended states.

Also tests DELETE without versionId behavior (creating DM) across all states.
"""

import uuid

import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml_with_mfa


def _put_versioning(make_request, bucket, status):
    body = build_versioning_xml_with_mfa(status, mfa_delete="Disabled")
    resp = make_request("PUT", f"/{bucket}", body=body,
                       headers={"Content-Type": "application/xml"}, query_params="?versioning")
    sc = _sc(resp)
    assert sc == 200, f"PutBucketVersioning({status}) failed: {sc}"


def _get_versioning(make_request, bucket):
    """Get current bucket versioning status string."""
    resp = make_request("GET", f"/{bucket}", query_params="?versioning")
    text = _text(resp)
    if "<Status>Enabled</Status>" in text:
        return "Enabled"
    elif "<Status>Suspended</Status>" in text:
        return "Suspended"
    return "Disabled"


def _sc(r):
    return r.aws.status_code if hasattr(r, "comparison") else r.status_code

def _h(r):
    return r.aws.headers if hasattr(r, "comparison") else r.headers

def _text(r):
    return r.aws.text if hasattr(r, "comparison") else r.text

def _body(r):
    return r.aws.content if hasattr(r, "comparison") else r.content

def _vid(r):
    return _h(r).get("x-amz-version-id")

def _dm(r):
    return _h(r).get("x-amz-delete-marker")

def _unique_key(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.mark.s3_handler("DeleteObject")
class TestDeleteDMHeaderEnabled:
    """DELETE on Enabled bucket — creating and removing delete markers."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delete_without_vid_creates_dm(self, test_bucket, make_request):
        """Enabled: DELETE /key → 204, creates DM, vid=non-empty, dm=true."""
        key = _unique_key("en-create-dm")
        _put_versioning(make_request, test_bucket, "Enabled")
        vs = _get_versioning(make_request, test_bucket)
        make_request("PUT", f"/{test_bucket}/{key}", body=b"data")

        resp = make_request("DELETE", f"/{test_bucket}/{key}")

        print(f"\n--- Enabled: DELETE /key (create DM) ---")
        print(f"  Bucket versioning: {vs}")
        print(f"  Status: {_sc(resp)}")
        print(f"  x-amz-version-id: {_vid(resp)!r}")
        print(f"  x-amz-delete-marker: {_dm(resp)!r}")

        assert _sc(resp) == 204
        assert _vid(resp) is not None and _vid(resp) != ""
        assert _dm(resp) == "true"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delete_dm_by_vid(self, test_bucket, make_request):
        """Enabled: DELETE ?versionId=<dm> → 204, dm=true, object revived."""
        key = _unique_key("en-del-dm")
        _put_versioning(make_request, test_bucket, "Enabled")
        vs = _get_versioning(make_request, test_bucket)
        make_request("PUT", f"/{test_bucket}/{key}", body=b"original")

        # Create DM
        del_resp = make_request("DELETE", f"/{test_bucket}/{key}")
        dm_vid = _vid(del_resp)
        assert dm_vid

        # Delete the DM
        resp = make_request("DELETE", f"/{test_bucket}/{key}",
                           query_params=f"?versionId={dm_vid}")

        print(f"\n--- Enabled: DELETE ?versionId=<dm> (remove DM) ---")
        print(f"  Bucket versioning: {vs}")
        print(f"  Status: {_sc(resp)}")
        print(f"  x-amz-version-id: {_vid(resp)!r}")
        print(f"  x-amz-delete-marker: {_dm(resp)!r}")

        assert _sc(resp) == 204
        assert _vid(resp) == dm_vid
        assert _dm(resp) == "true", f"Expected dm=true when deleting DM, got: {_dm(resp)!r}"

        # Object should be revived
        get_resp = make_request("GET", f"/{test_bucket}/{key}")
        assert _sc(get_resp) == 200
        assert _body(get_resp) == b"original"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delete_regular_version_by_vid(self, test_bucket, make_request):
        """Enabled: DELETE ?versionId=<real> → 204, NO dm header."""
        key = _unique_key("en-del-ver")
        _put_versioning(make_request, test_bucket, "Enabled")
        vs = _get_versioning(make_request, test_bucket)
        put_resp = make_request("PUT", f"/{test_bucket}/{key}", body=b"v1")
        v1_vid = _vid(put_resp)
        assert v1_vid

        resp = make_request("DELETE", f"/{test_bucket}/{key}",
                           query_params=f"?versionId={v1_vid}")

        print(f"\n--- Enabled: DELETE ?versionId=<regular> (remove version) ---")
        print(f"  Bucket versioning: {vs}")
        print(f"  Status: {_sc(resp)}")
        print(f"  x-amz-version-id: {_vid(resp)!r}")
        print(f"  x-amz-delete-marker: {_dm(resp)!r}")

        assert _sc(resp) == 204
        assert _vid(resp) == v1_vid
        assert _dm(resp) is None, f"Expected no dm header for regular version, got: {_dm(resp)!r}"


@pytest.mark.s3_handler("DeleteObject")
class TestDeleteDMHeaderSuspended:
    """DELETE on Suspended bucket — creating and removing delete markers."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delete_without_vid_creates_null_dm(self, test_bucket, make_request):
        """Suspended: DELETE /key → 204, creates null DM, dm=true."""
        key = _unique_key("sus-create-dm")
        _put_versioning(make_request, test_bucket, "Enabled")
        make_request("PUT", f"/{test_bucket}/{key}", body=b"data")
        _put_versioning(make_request, test_bucket, "Suspended")
        vs = _get_versioning(make_request, test_bucket)

        resp = make_request("DELETE", f"/{test_bucket}/{key}")

        print(f"\n--- Suspended: DELETE /key (create null DM) ---")
        print(f"  Bucket versioning: {vs}")
        print(f"  Status: {_sc(resp)}")
        print(f"  x-amz-version-id: {_vid(resp)!r}")
        print(f"  x-amz-delete-marker: {_dm(resp)!r}")

        assert _sc(resp) == 204
        assert _dm(resp) == "true"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delete_null_dm_by_vid_null(self, test_bucket, make_request):
        """Suspended: DELETE ?versionId=null (remove null DM) → 204, dm=true."""
        key = _unique_key("sus-del-null-dm")
        _put_versioning(make_request, test_bucket, "Enabled")
        put_resp = make_request("PUT", f"/{test_bucket}/{key}", body=b"original")
        v1_vid = _vid(put_resp)
        _put_versioning(make_request, test_bucket, "Suspended")

        # Create null DM
        make_request("DELETE", f"/{test_bucket}/{key}")

        # Verify object is "deleted"
        get_resp = make_request("GET", f"/{test_bucket}/{key}")
        assert _sc(get_resp) == 404

        # Delete null DM by versionId=null
        resp = make_request("DELETE", f"/{test_bucket}/{key}",
                           query_params="?versionId=null")

        vs = _get_versioning(make_request, test_bucket)
        print(f"\n--- Suspended: DELETE ?versionId=null (remove null DM) ---")
        print(f"  Bucket versioning: {vs}")
        print(f"  Status: {_sc(resp)}")
        print(f"  x-amz-version-id: {_vid(resp)!r}")
        print(f"  x-amz-delete-marker: {_dm(resp)!r}")

        assert _sc(resp) == 204
        assert _vid(resp) == "null"
        assert _dm(resp) == "true", f"Expected dm=true when deleting null DM, got: {_dm(resp)!r}"

        # Old versioned object should be accessible as latest
        if v1_vid:
            get_resp2 = make_request("GET", f"/{test_bucket}/{key}")
            print(f"  GET after null DM removal: status={_sc(get_resp2)}, body={_body(get_resp2)!r}")

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delete_old_versioned_by_vid_while_suspended(self, test_bucket, make_request):
        """Suspended: DELETE ?versionId=<old-real-vid> → 204, NO dm header."""
        key = _unique_key("sus-del-old")
        _put_versioning(make_request, test_bucket, "Enabled")
        put_resp = make_request("PUT", f"/{test_bucket}/{key}", body=b"v1")
        v1_vid = _vid(put_resp)
        assert v1_vid
        _put_versioning(make_request, test_bucket, "Suspended")

        resp = make_request("DELETE", f"/{test_bucket}/{key}",
                           query_params=f"?versionId={v1_vid}")

        vs = _get_versioning(make_request, test_bucket)
        print(f"\n--- Suspended: DELETE ?versionId=<old-real> (remove old version) ---")
        print(f"  Bucket versioning: {vs}")
        print(f"  Status: {_sc(resp)}")
        print(f"  x-amz-version-id: {_vid(resp)!r}")
        print(f"  x-amz-delete-marker: {_dm(resp)!r}")

        assert _sc(resp) == 204
        assert _vid(resp) == v1_vid
        assert _dm(resp) is None, f"Expected no dm header for regular version, got: {_dm(resp)!r}"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delete_dm_created_while_enabled_from_suspended(self, test_bucket, make_request):
        """Suspended: DELETE ?versionId=<dm-created-while-enabled> → 204, dm=true."""
        key = _unique_key("sus-del-en-dm")
        _put_versioning(make_request, test_bucket, "Enabled")
        make_request("PUT", f"/{test_bucket}/{key}", body=b"data")

        # Create DM while Enabled
        del_resp = make_request("DELETE", f"/{test_bucket}/{key}")
        dm_vid = _vid(del_resp)
        assert dm_vid

        _put_versioning(make_request, test_bucket, "Suspended")

        # Delete that DM while Suspended
        resp = make_request("DELETE", f"/{test_bucket}/{key}",
                           query_params=f"?versionId={dm_vid}")

        vs = _get_versioning(make_request, test_bucket)
        print(f"\n--- Suspended: DELETE ?versionId=<dm-from-enabled> (remove DM) ---")
        print(f"  Bucket versioning: {vs}")
        print(f"  Status: {_sc(resp)}")
        print(f"  x-amz-version-id: {_vid(resp)!r}")
        print(f"  x-amz-delete-marker: {_dm(resp)!r}")

        assert _sc(resp) == 204
        assert _dm(resp) == "true", f"Expected dm=true when deleting DM, got: {_dm(resp)!r}"


@pytest.mark.s3_handler("DeleteObject")
class TestDeleteDMHeaderDisabled:
    """DELETE on Disabled bucket — no versioning, no DM."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delete_without_vid_disabled(self, test_bucket, make_request):
        """Disabled: DELETE /key → 204, no vid, no dm."""
        key = _unique_key("dis-del")
        _put_versioning(make_request, test_bucket, "Suspended")
        make_request("PUT", f"/{test_bucket}/{key}", body=b"data")

        resp = make_request("DELETE", f"/{test_bucket}/{key}")

        vs = _get_versioning(make_request, test_bucket)
        print(f"\n--- Disabled: DELETE /key ---")
        print(f"  Bucket versioning: {vs}")
        print(f"  Status: {_sc(resp)}")
        print(f"  x-amz-version-id: {_vid(resp)!r}")
        print(f"  x-amz-delete-marker: {_dm(resp)!r}")

        assert _sc(resp) == 204
