"""DeleteObjects versioning tests.

Tests DeleteObjects (batch) behavior across versioning states:
- A: Versioning Suspended (as disabled proxy)
- B: Versioning Enabled — without versionId
- C: Versioning Enabled — with versionId
- D: Versioning Enabled — mix with/without versionId
- E: Versioning Suspended (after Enabled)
- F: Quiet mode

Converted from scripts/probe_deleteobjects_versioning.py.
Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import uuid
from xml.etree import ElementTree as ET

import pytest

from s3_compliance.utils import calculate_content_md5
from tests.put_bucket_versioning.conftest import build_versioning_xml_with_mfa


S3_NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _unique_key(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _sc(resp):
    return resp.aws.status_code if hasattr(resp, "comparison") else resp.status_code


def _text(resp):
    return resp.aws.text if hasattr(resp, "comparison") else resp.text


def _h(resp):
    return resp.aws.headers if hasattr(resp, "comparison") else resp.headers


def _vid(resp):
    return _h(resp).get("x-amz-version-id")


def _put_versioning(make_request, bucket, status):
    body = build_versioning_xml_with_mfa(status, mfa_delete="Disabled")
    resp = make_request("PUT", f"/{bucket}", body=body,
                        headers={"Content-Type": "application/xml"}, query_params="?versioning")
    assert _sc(resp) == 200, f"PutBucketVersioning({status}) failed: {_sc(resp)}"


def _put_object(make_request, bucket, key, body_bytes=b"data"):
    resp = make_request("PUT", f"/{bucket}/{key}", body=body_bytes)
    assert _sc(resp) == 200, f"PutObject failed: {_sc(resp)}"
    return _vid(resp)


def _delete_object(make_request, bucket, key, version_id=None):
    qp = f"?versionId={version_id}" if version_id else ""
    return make_request("DELETE", f"/{bucket}/{key}", query_params=qp)


def _delete_objects_raw(make_request, bucket, objects_xml, quiet=False):
    """Send raw DeleteObjects POST and return response."""
    quiet_xml = "<Quiet>true</Quiet>" if quiet else ""
    xml_body = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        f'{quiet_xml}'
        f'{objects_xml}'
        f'</Delete>'
    )
    body = xml_body.encode("utf-8")
    headers = {
        "Content-Type": "application/xml",
        "Content-MD5": calculate_content_md5(body),
    }
    return make_request("POST", f"/{bucket}", body=body, headers=headers, query_params="?delete")


def _obj_xml(key, version_id=None):
    vid = f"<VersionId>{version_id}</VersionId>" if version_id else ""
    return f"<Object><Key>{key}</Key>{vid}</Object>"


def _parse_deleted(resp_text):
    """Parse <Deleted> elements from DeleteResult XML.

    Returns list of dicts with keys: Key, VersionId, DeleteMarker, DeleteMarkerVersionId.
    """
    result = []
    try:
        root = ET.fromstring(resp_text)
        for deleted in root.findall(f".//{S3_NS}Deleted"):
            entry = {}
            key_el = deleted.find(f"{S3_NS}Key")
            if key_el is not None:
                entry["Key"] = key_el.text
            vid_el = deleted.find(f"{S3_NS}VersionId")
            if vid_el is not None:
                entry["VersionId"] = vid_el.text
            dm_el = deleted.find(f"{S3_NS}DeleteMarker")
            if dm_el is not None:
                entry["DeleteMarker"] = dm_el.text
            dmvid_el = deleted.find(f"{S3_NS}DeleteMarkerVersionId")
            if dmvid_el is not None:
                entry["DeleteMarkerVersionId"] = dmvid_el.text
            result.append(entry)
    except ET.ParseError:
        pass
    return result


def _parse_errors(resp_text):
    """Parse <Error> elements from DeleteResult XML."""
    result = []
    try:
        root = ET.fromstring(resp_text)
        for error in root.findall(f".//{S3_NS}Error"):
            entry = {}
            for field in ("Key", "Code", "Message", "VersionId"):
                el = error.find(f"{S3_NS}{field}")
                if el is not None:
                    entry[field] = el.text
            result.append(entry)
    except ET.ParseError:
        pass
    return result


# ===========================================================================
# A. Versioning Suspended (as disabled proxy)
# ===========================================================================

@pytest.mark.s3_handler("DeleteObjects")
class TestDeleteObjectsSuspendedAsDisabled:
    """DeleteObjects when versioning is suspended (never enabled in these tests)."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_a1_delete_existing(self, test_bucket, make_request, json_metadata):
        """A1: Suspended — delete existing object → <Deleted> with DM=true, DMVersionId=null."""
        _put_versioning(make_request, test_bucket, "Suspended")
        key = _unique_key("delobj-a1")
        _put_object(make_request, test_bucket, key)

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1
        assert deleted[0]["Key"] == key
        assert deleted[0].get("DeleteMarker") == "true"
        assert deleted[0].get("DeleteMarkerVersionId") == "null"
        assert "VersionId" not in deleted[0]

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_a2_delete_nonexistent(self, test_bucket, make_request, json_metadata):
        """A2: Suspended — delete nonexistent → <Deleted> (no error)."""
        _put_versioning(make_request, test_bucket, "Suspended")
        key = _unique_key("delobj-a2")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1
        assert deleted[0]["Key"] == key
        assert deleted[0].get("DeleteMarker") == "true"
        assert deleted[0].get("DeleteMarkerVersionId") == "null"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_a3_delete_two_different(self, test_bucket, make_request, json_metadata):
        """A3: Suspended — delete two different objects in one request."""
        _put_versioning(make_request, test_bucket, "Suspended")
        k1 = _unique_key("delobj-a3a")
        k2 = _unique_key("delobj-a3b")
        _put_object(make_request, test_bucket, k1, b"a")
        _put_object(make_request, test_bucket, k2, b"b")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(k1) + _obj_xml(k2))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 2
        keys = {d["Key"] for d in deleted}
        assert keys == {k1, k2}

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_a4_same_key_twice_dedup(self, test_bucket, make_request, json_metadata):
        """A4: Suspended — same key twice → AWS deduplicates to one <Deleted>."""
        _put_versioning(make_request, test_bucket, "Suspended")
        key = _unique_key("delobj-a4")
        _put_object(make_request, test_bucket, key, b"data")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key) + _obj_xml(key))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        # AWS returns 1 <Deleted> (deduplication)
        assert len(deleted) == 1, (
            f"Expected 1 <Deleted> (dedup), got {len(deleted)}: {_text(resp)[:500]}"
        )
        assert deleted[0]["Key"] == key


# ===========================================================================
# B. Versioning Enabled — without versionId
# ===========================================================================

@pytest.mark.s3_handler("DeleteObjects")
class TestDeleteObjectsEnabledNoVid:
    """DeleteObjects on enabled bucket without versionId."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_b1_delete_existing_creates_dm(self, test_bucket, make_request, json_metadata):
        """B1: Enabled — delete existing → DM created, response has DeleteMarker+DeleteMarkerVersionId."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-b1")
        _put_object(make_request, test_bucket, key, b"data")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1
        assert deleted[0]["Key"] == key
        assert deleted[0].get("DeleteMarker") == "true"
        dm_vid = deleted[0].get("DeleteMarkerVersionId")
        assert dm_vid is not None and dm_vid != "" and dm_vid != "null"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_b2_delete_nonexistent_creates_dm(self, test_bucket, make_request, json_metadata):
        """B2: Enabled — delete nonexistent → DM created."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-b2")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1
        assert deleted[0].get("DeleteMarker") == "true"
        assert deleted[0].get("DeleteMarkerVersionId") not in (None, "", "null")

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_b3_same_key_twice_dedup_one_dm(self, test_bucket, make_request, json_metadata):
        """B3: Enabled — same key twice → AWS deduplicates to 1 <Deleted>, creates 1 DM."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-b3")
        _put_object(make_request, test_bucket, key, b"data")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key) + _obj_xml(key))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        # AWS returns 1 <Deleted> with 1 DM (deduplication)
        assert len(deleted) == 1, (
            f"Expected 1 <Deleted> (dedup), got {len(deleted)}: {_text(resp)[:500]}"
        )
        assert deleted[0].get("DeleteMarker") == "true"


# ===========================================================================
# Dedup: same key with various versionId combinations
# ===========================================================================

@pytest.mark.s3_handler("DeleteObjects")
class TestDeleteObjectsDedup:
    """AWS deduplicates by exact (key, versionId) pair.

    Deduplicates:
      [no vid] + [no vid]       → 1  (tested in A4, B3)
      [vid=A]  + [vid=A]        → 1
      [vid=null] + [vid=null]   → 1

    Does NOT deduplicate:
      [vid=A]  + [vid=B]        → 2  (different versionIds)
      [no vid] + [vid=null]     → 2  (bare ≠ null)
      [no vid] + [vid=A]        → 2  (bare ≠ vid)
    """

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_same_vid_twice_dedup(self, test_bucket, make_request, json_metadata):
        """[vid=A] + [vid=A] — same versionId twice → AWS returns 1 (dedup)."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("dedup-samevid")
        v1 = _put_object(make_request, test_bucket, key, b"v1")
        _put_object(make_request, test_bucket, key, b"v2")

        resp = _delete_objects_raw(make_request, test_bucket,
                                   _obj_xml(key, v1) + _obj_xml(key, v1))
        assert _sc(resp) == 200
        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1, (
            f"Expected 1 <Deleted> (dedup vid=A twice), got {len(deleted)}: {_text(resp)[:500]}"
        )
        assert deleted[0].get("VersionId") == v1

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_vid_null_twice_dedup(self, test_bucket, make_request, json_metadata):
        """[vid=null] + [vid=null] — versionId=null twice → AWS returns 1 (dedup)."""
        _put_versioning(make_request, test_bucket, "Suspended")
        key = _unique_key("dedup-nullvid")
        _put_object(make_request, test_bucket, key, b"null-ver")

        resp = _delete_objects_raw(make_request, test_bucket,
                                   _obj_xml(key, "null") + _obj_xml(key, "null"))
        assert _sc(resp) == 200
        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1, (
            f"Expected 1 <Deleted> (dedup vid=null twice), got {len(deleted)}: {_text(resp)[:500]}"
        )
        assert deleted[0].get("VersionId") == "null"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_two_different_vids_no_dedup(self, test_bucket, make_request, json_metadata):
        """[vid=A] + [vid=B] — different versionIds → 2 (no dedup)."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("dedup-diffvid")
        v1 = _put_object(make_request, test_bucket, key, b"v1")
        v2 = _put_object(make_request, test_bucket, key, b"v2")

        resp = _delete_objects_raw(make_request, test_bucket,
                                   _obj_xml(key, v1) + _obj_xml(key, v2))
        assert _sc(resp) == 200
        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 2
        vids = {d.get("VersionId") for d in deleted}
        assert vids == {v1, v2}

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_bare_plus_vid_null_no_dedup(self, test_bucket, make_request, json_metadata):
        """[no vid] + [vid=null] — bare ≠ null → 2 (no dedup)."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("dedup-bare-null")
        _put_versioning(make_request, test_bucket, "Suspended")
        _put_object(make_request, test_bucket, key, b"null-ver")
        _put_versioning(make_request, test_bucket, "Enabled")

        resp = _delete_objects_raw(make_request, test_bucket,
                                   _obj_xml(key) + _obj_xml(key, "null"))
        assert _sc(resp) == 200
        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 2, (
            f"Expected 2 <Deleted> (bare ≠ null, no dedup), got {len(deleted)}: {_text(resp)[:500]}"
        )

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_bare_plus_vid_no_dedup(self, test_bucket, make_request, json_metadata):
        """[no vid] + [vid=A] — bare ≠ vid → 2 (no dedup)."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("dedup-bare-vid")
        v1 = _put_object(make_request, test_bucket, key, b"v1")
        _put_object(make_request, test_bucket, key, b"v2")

        resp = _delete_objects_raw(make_request, test_bucket,
                                   _obj_xml(key) + _obj_xml(key, v1))
        assert _sc(resp) == 200
        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 2, (
            f"Expected 2 <Deleted> (bare ≠ vid, no dedup), got {len(deleted)}: {_text(resp)[:500]}"
        )


# ===========================================================================
# C. Versioning Enabled — with versionId
# ===========================================================================

@pytest.mark.s3_handler("DeleteObjects")
class TestDeleteObjectsEnabledWithVid:
    """DeleteObjects on enabled bucket with specific versionId."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_c1_delete_specific_version(self, test_bucket, make_request, json_metadata):
        """C1: Enabled — delete old version by vid → <Deleted> with VersionId, no DeleteMarker."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-c1")
        v1 = _put_object(make_request, test_bucket, key, b"v1")
        _put_object(make_request, test_bucket, key, b"v2")
        assert v1, "v1 version id empty"

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key, v1))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1
        assert deleted[0]["Key"] == key
        assert deleted[0].get("VersionId") == v1
        assert "DeleteMarker" not in deleted[0]
        assert "DeleteMarkerVersionId" not in deleted[0]

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_c2_delete_nonexistent_vid(self, test_bucket, make_request, json_metadata):
        """C2: Enabled — delete non-existent versionId → <Deleted> (not error), no side effect."""
        _put_versioning(make_request, test_bucket, "Enabled")
        k1 = _unique_key("delobj-c2a")
        k2 = _unique_key("delobj-c2b")
        _put_object(make_request, test_bucket, k1, b"data")
        wrong_vid = _put_object(make_request, test_bucket, k2, b"other")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(k1, wrong_vid))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1
        assert deleted[0]["Key"] == k1
        assert deleted[0].get("VersionId") == wrong_vid

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_c3_delete_dm_by_vid(self, test_bucket, make_request, json_metadata):
        """C3: Enabled — delete DM by versionId → DeleteMarker=true + DeleteMarkerVersionId in response."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-c3")
        _put_object(make_request, test_bucket, key, b"data")

        # Create DM
        del_resp = _delete_object(make_request, test_bucket, key)
        dm_vid = _vid(del_resp)
        assert dm_vid, "DM version id empty"

        # Delete the DM by versionId via DeleteObjects
        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key, dm_vid))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1
        assert deleted[0]["Key"] == key
        assert deleted[0].get("VersionId") == dm_vid
        # AWS returns DeleteMarker=true and DeleteMarkerVersionId=same vid when deleting a DM
        assert deleted[0].get("DeleteMarker") == "true", (
            f"Expected DeleteMarker=true when deleting DM, got: {deleted[0]}"
        )
        assert deleted[0].get("DeleteMarkerVersionId") == dm_vid, (
            f"Expected DeleteMarkerVersionId={dm_vid}, got: {deleted[0]}"
        )

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_c4_delete_only_version(self, test_bucket, make_request, json_metadata):
        """C4: Enabled — delete only version by vid → object fully gone."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-c4")
        v1 = _put_object(make_request, test_bucket, key, b"only")
        assert v1

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key, v1))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1
        assert deleted[0].get("VersionId") == v1

        # Object should be gone
        get_resp = make_request("GET", f"/{test_bucket}/{key}")
        assert _sc(get_resp) == 404


# ===========================================================================
# D. Versioning Enabled — mix with/without versionId
# ===========================================================================

@pytest.mark.s3_handler("DeleteObjects")
class TestDeleteObjectsEnabledMix:
    """DeleteObjects with mixed versionId / no-versionId in same request."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_d1_same_key_vid_plus_bare(self, test_bucket, make_request, json_metadata):
        """D1: Enabled — same key [with vid] + [without vid] → both succeed."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-d1")
        v1 = _put_object(make_request, test_bucket, key, b"v1")
        _put_object(make_request, test_bucket, key, b"v2")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key, v1) + _obj_xml(key))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 2

        # One should be vid-based delete, one should be DM creation
        vid_deletes = [d for d in deleted if d.get("VersionId") and "DeleteMarker" not in d]
        dm_deletes = [d for d in deleted if d.get("DeleteMarker") == "true"]
        assert len(vid_deletes) == 1
        assert len(dm_deletes) == 1
        assert vid_deletes[0]["VersionId"] == v1

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_d2_same_key_bare_plus_vid(self, test_bucket, make_request, json_metadata):
        """D2: Enabled — same key [without vid] + [with vid] → both succeed."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-d2")
        v1 = _put_object(make_request, test_bucket, key, b"v1")
        _put_object(make_request, test_bucket, key, b"v2")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key) + _obj_xml(key, v1))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 2

        vid_deletes = [d for d in deleted if d.get("VersionId") and "DeleteMarker" not in d]
        dm_deletes = [d for d in deleted if d.get("DeleteMarker") == "true"]
        assert len(vid_deletes) == 1
        assert len(dm_deletes) == 1
        assert vid_deletes[0]["VersionId"] == v1

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_d3_delete_latest_vid_plus_bare(self, test_bucket, make_request, json_metadata):
        """D3: Enabled — same key [delete LATEST by vid] + [without vid] → both succeed."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-d3")
        _put_object(make_request, test_bucket, key, b"v1")
        v2 = _put_object(make_request, test_bucket, key, b"v2")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key, v2) + _obj_xml(key))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 2

        vid_deletes = [d for d in deleted if d.get("VersionId") and "DeleteMarker" not in d]
        dm_deletes = [d for d in deleted if d.get("DeleteMarker") == "true"]
        assert len(vid_deletes) == 1
        assert len(dm_deletes) == 1

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_d4_different_keys_vid_and_bare(self, test_bucket, make_request, json_metadata):
        """D4: Enabled — two different keys, one with vid, one without → both in <Deleted>."""
        _put_versioning(make_request, test_bucket, "Enabled")
        k1 = _unique_key("delobj-d4a")
        k2 = _unique_key("delobj-d4b")
        v1 = _put_object(make_request, test_bucket, k1, b"a")
        _put_object(make_request, test_bucket, k2, b"b")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(k1, v1) + _obj_xml(k2))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 2

        keys = {d["Key"] for d in deleted}
        assert keys == {k1, k2}

        # k1 should be vid-based delete
        k1_del = [d for d in deleted if d["Key"] == k1][0]
        assert k1_del.get("VersionId") == v1
        assert "DeleteMarker" not in k1_del

        # k2 should be DM creation
        k2_del = [d for d in deleted if d["Key"] == k2][0]
        assert k2_del.get("DeleteMarker") == "true"
        assert k2_del.get("DeleteMarkerVersionId") not in (None, "", "null")


# ===========================================================================
# E. Versioning Suspended (after Enabled)
# ===========================================================================

@pytest.mark.s3_handler("DeleteObjects")
class TestDeleteObjectsSuspended:
    """DeleteObjects when versioning is suspended (was previously enabled)."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_e1_delete_existing_creates_null_dm(self, test_bucket, make_request, json_metadata):
        """E1: Suspended — delete existing → null DM."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-e1")
        _put_object(make_request, test_bucket, key, b"data")
        _put_versioning(make_request, test_bucket, "Suspended")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1
        assert deleted[0].get("DeleteMarker") == "true"
        assert deleted[0].get("DeleteMarkerVersionId") == "null"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_e2_delete_nonexistent(self, test_bucket, make_request, json_metadata):
        """E2: Suspended — delete nonexistent → null DM."""
        _put_versioning(make_request, test_bucket, "Suspended")
        key = _unique_key("delobj-e2")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1
        assert deleted[0].get("DeleteMarker") == "true"
        assert deleted[0].get("DeleteMarkerVersionId") == "null"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_e3_delete_old_version_by_vid(self, test_bucket, make_request, json_metadata):
        """E3: Suspended — delete old version (created while Enabled) by vid."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-e3")
        v1 = _put_object(make_request, test_bucket, key, b"data")
        assert v1
        _put_versioning(make_request, test_bucket, "Suspended")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key, v1))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1
        assert deleted[0].get("VersionId") == v1
        assert "DeleteMarker" not in deleted[0]

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_e4_delete_with_vid_null(self, test_bucket, make_request, json_metadata):
        """E4: Suspended — delete with versionId=null → removes null version."""
        _put_versioning(make_request, test_bucket, "Suspended")
        key = _unique_key("delobj-e4")
        _put_object(make_request, test_bucket, key, b"null-ver")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key, "null"))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 1
        assert deleted[0].get("VersionId") == "null"
        assert "DeleteMarker" not in deleted[0]

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_e5_mix_bare_plus_old_vid(self, test_bucket, make_request, json_metadata):
        """E5: Suspended — same key [no vid] + [old vid] → both succeed."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-e5")
        v1 = _put_object(make_request, test_bucket, key, b"data")
        assert v1
        _put_versioning(make_request, test_bucket, "Suspended")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key) + _obj_xml(key, v1))
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        assert len(deleted) == 2

        vid_deletes = [d for d in deleted if d.get("VersionId") and "DeleteMarker" not in d]
        dm_deletes = [d for d in deleted if d.get("DeleteMarker") == "true"]
        assert len(vid_deletes) == 1
        assert len(dm_deletes) == 1
        assert vid_deletes[0]["VersionId"] == v1
        assert dm_deletes[0].get("DeleteMarkerVersionId") == "null"


# ===========================================================================
# F. Quiet mode
# ===========================================================================

@pytest.mark.s3_handler("DeleteObjects")
class TestDeleteObjectsQuiet:
    """DeleteObjects with Quiet=true."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_f1_quiet_successful(self, test_bucket, make_request, json_metadata):
        """F1: Enabled — Quiet=true → empty <DeleteResult>."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-f1")
        _put_object(make_request, test_bucket, key, b"data")

        resp = _delete_objects_raw(make_request, test_bucket, _obj_xml(key), quiet=True)
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        errors = _parse_errors(_text(resp))
        assert len(deleted) == 0, f"Quiet mode should return no <Deleted>, got: {_text(resp)[:500]}"
        assert len(errors) == 0

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_f2_quiet_existing_plus_nonexistent(self, test_bucket, make_request, json_metadata):
        """F2: Enabled — Quiet=true, existing + nonexistent → empty <DeleteResult>."""
        _put_versioning(make_request, test_bucket, "Enabled")
        key = _unique_key("delobj-f2")
        _put_object(make_request, test_bucket, key, b"data")
        nonexistent = _unique_key("nonexistent")

        resp = _delete_objects_raw(
            make_request, test_bucket,
            _obj_xml(key) + _obj_xml(nonexistent),
            quiet=True,
        )
        assert _sc(resp) == 200

        deleted = _parse_deleted(_text(resp))
        errors = _parse_errors(_text(resp))
        assert len(deleted) == 0
        assert len(errors) == 0
