"""Tests for ListObjectVersions with mixed versions and delete markers.

Verifies correct behavior when the bucket contains both Version entries
and DeleteMarker entries in the ListVersionsResult response.

Based on empirical AWS data from listobj/list_versions_short.log scenarios 4-14.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import xml.etree.ElementTree as ET

import pytest

from .conftest import build_versions_query


NS = "http://s3.amazonaws.com/doc/2006-03-01/"


def _parse_list_versions(text):
    """Parse ListVersionsResult XML into structured data."""
    root = ET.fromstring(text)
    versions = []
    delete_markers = []

    for v in root.findall(f"{{{NS}}}Version"):
        versions.append({
            "key": v.findtext(f"{{{NS}}}Key"),
            "version_id": v.findtext(f"{{{NS}}}VersionId"),
            "is_latest": v.findtext(f"{{{NS}}}IsLatest"),
            "size": v.findtext(f"{{{NS}}}Size"),
            "etag": v.findtext(f"{{{NS}}}ETag"),
        })
    for dm in root.findall(f"{{{NS}}}DeleteMarker"):
        delete_markers.append({
            "key": dm.findtext(f"{{{NS}}}Key"),
            "version_id": dm.findtext(f"{{{NS}}}VersionId"),
            "is_latest": dm.findtext(f"{{{NS}}}IsLatest"),
        })

    return {
        "name": root.findtext(f"{{{NS}}}Name"),
        "prefix": root.findtext(f"{{{NS}}}Prefix"),
        "max_keys": root.findtext(f"{{{NS}}}MaxKeys"),
        "is_truncated": root.findtext(f"{{{NS}}}IsTruncated"),
        "versions": versions,
        "delete_markers": delete_markers,
    }


def _get_response(response):
    if hasattr(response, "comparison"):
        return response.aws
    return response


def _assert_200(response):
    if hasattr(response, "comparison"):
        assert response.aws.status_code == 200, (
            f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:300]}"
        )
    else:
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text[:300]}"
        )


@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestListVersionsWithMixedContent:
    """ListObjectVersions on a bucket with both versions and delete markers.

    Uses bucket_with_versions_and_markers fixture:
      - obj-alive: 2 versions (latest = Version)
      - obj-deleted: 1 version + delete marker (latest = DeleteMarker)
      - obj-revived: version + delete marker + version (latest = Version)
    """

    def test_both_versions_and_markers_present(
        self, test_bucket, make_request, json_metadata,
        bucket_with_versions_and_markers,
    ):
        """Response contains both <Version> and <DeleteMarker> elements."""
        prefix = bucket_with_versions_and_markers["prefix"]
        query = build_versions_query(prefix=prefix)

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)

        json_metadata["version_count"] = len(parsed["versions"])
        json_metadata["delete_marker_count"] = len(parsed["delete_markers"])

        assert len(parsed["versions"]) > 0, "Expected at least one Version entry"
        assert len(parsed["delete_markers"]) > 0, "Expected at least one DeleteMarker entry"

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    def test_alive_object_has_two_versions(
        self, test_bucket, make_request, json_metadata,
        bucket_with_versions_and_markers,
    ):
        """obj-alive should have exactly 2 Version entries, no DeleteMarkers."""
        info = bucket_with_versions_and_markers
        key = info["keys"]["alive"]["key"]
        prefix = info["prefix"]
        query = build_versions_query(prefix=prefix)

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)

        alive_versions = [v for v in parsed["versions"] if v["key"] == key]
        alive_markers = [d for d in parsed["delete_markers"] if d["key"] == key]

        json_metadata["key"] = key
        json_metadata["versions"] = len(alive_versions)
        json_metadata["delete_markers"] = len(alive_markers)

        assert len(alive_versions) == 2, (
            f"Expected 2 versions for {key}, got {len(alive_versions)}"
        )
        assert len(alive_markers) == 0, (
            f"Expected 0 delete markers for {key}, got {len(alive_markers)}"
        )
        assert alive_versions[0]["is_latest"] == "true"
        assert alive_versions[1]["is_latest"] == "false"

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    def test_deleted_object_has_delete_marker_as_latest(
        self, test_bucket, make_request, json_metadata,
        bucket_with_versions_and_markers,
    ):
        """obj-deleted should have DeleteMarker as latest, Version as non-latest."""
        info = bucket_with_versions_and_markers
        key = info["keys"]["deleted"]["key"]
        prefix = info["prefix"]
        query = build_versions_query(prefix=prefix)

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)

        del_versions = [v for v in parsed["versions"] if v["key"] == key]
        del_markers = [d for d in parsed["delete_markers"] if d["key"] == key]

        json_metadata["key"] = key
        json_metadata["versions"] = len(del_versions)
        json_metadata["delete_markers"] = len(del_markers)

        assert len(del_markers) >= 1, (
            f"Expected at least 1 delete marker for {key}, got {len(del_markers)}"
        )
        assert len(del_versions) >= 1, (
            f"Expected at least 1 version for {key}, got {len(del_versions)}"
        )

        # Delete marker should be latest
        latest_marker = [d for d in del_markers if d["is_latest"] == "true"]
        assert len(latest_marker) == 1, (
            f"Expected exactly 1 latest delete marker for {key}"
        )

        # Version should not be latest
        latest_versions = [v for v in del_versions if v["is_latest"] == "true"]
        assert len(latest_versions) == 0, (
            f"Expected no latest version for deleted object {key}, got {len(latest_versions)}"
        )

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    def test_revived_object_has_version_as_latest(
        self, test_bucket, make_request, json_metadata,
        bucket_with_versions_and_markers,
    ):
        """obj-revived: put → delete → put. Latest should be Version, not DeleteMarker."""
        info = bucket_with_versions_and_markers
        key = info["keys"]["revived"]["key"]
        prefix = info["prefix"]
        query = build_versions_query(prefix=prefix)

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)

        rev_versions = [v for v in parsed["versions"] if v["key"] == key]
        rev_markers = [d for d in parsed["delete_markers"] if d["key"] == key]

        json_metadata["key"] = key
        json_metadata["versions"] = len(rev_versions)
        json_metadata["delete_markers"] = len(rev_markers)

        # Should have 2 versions and 1 delete marker
        assert len(rev_versions) == 2, (
            f"Expected 2 versions for {key}, got {len(rev_versions)}"
        )
        assert len(rev_markers) == 1, (
            f"Expected 1 delete marker for {key}, got {len(rev_markers)}"
        )

        # Latest should be a version (the revived one)
        latest_versions = [v for v in rev_versions if v["is_latest"] == "true"]
        assert len(latest_versions) == 1, (
            f"Expected exactly 1 latest version for revived {key}"
        )

        # Delete marker should NOT be latest
        assert rev_markers[0]["is_latest"] == "false", (
            f"Delete marker for revived {key} should not be latest"
        )

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    def test_ordering_within_same_key(
        self, test_bucket, make_request, json_metadata,
        bucket_with_versions_and_markers,
    ):
        """All entries for same key are grouped together, latest first."""
        prefix = bucket_with_versions_and_markers["prefix"]
        query = build_versions_query(prefix=prefix)

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)

        # Collect all entries in order
        all_entries = []
        # We need to parse the raw XML to get insertion order
        root = ET.fromstring(resp.text)
        for child in root:
            tag = child.tag.replace(f"{{{NS}}}", "")
            if tag in ("Version", "DeleteMarker"):
                key = child.findtext(f"{{{NS}}}Key")
                is_latest = child.findtext(f"{{{NS}}}IsLatest")
                all_entries.append({"key": key, "is_latest": is_latest, "type": tag})

        # Group by key and verify ordering
        by_key = {}
        for entry in all_entries:
            by_key.setdefault(entry["key"], []).append(entry)

        for key, entries in by_key.items():
            if not entries:
                continue
            # First entry for each key should be is_latest=true
            assert entries[0]["is_latest"] == "true", (
                f"First entry for {key} should be latest, got is_latest={entries[0]['is_latest']}"
            )
            # Only one entry should be latest
            latest_count = sum(1 for e in entries if e["is_latest"] == "true")
            assert latest_count == 1, (
                f"Expected exactly 1 latest entry for {key}, got {latest_count}"
            )

        json_metadata["keys_checked"] = list(by_key.keys())

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    def test_delete_marker_has_no_size_or_etag(
        self, test_bucket, make_request, json_metadata,
        bucket_with_versions_and_markers,
    ):
        """DeleteMarker entries must NOT contain Size or ETag elements."""
        prefix = bucket_with_versions_and_markers["prefix"]
        query = build_versions_query(prefix=prefix)

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)

        root = ET.fromstring(resp.text)
        for dm in root.findall(f"{{{NS}}}DeleteMarker"):
            key = dm.findtext(f"{{{NS}}}Key")
            size_el = dm.find(f"{{{NS}}}Size")
            etag_el = dm.find(f"{{{NS}}}ETag")
            assert size_el is None, (
                f"DeleteMarker for {key} should not have Size element"
            )
            assert etag_el is None, (
                f"DeleteMarker for {key} should not have ETag element"
            )

        # Version entries MUST have Size and ETag
        for v in root.findall(f"{{{NS}}}Version"):
            key = v.findtext(f"{{{NS}}}Key")
            assert v.find(f"{{{NS}}}Size") is not None, (
                f"Version for {key} must have Size element"
            )
            assert v.find(f"{{{NS}}}ETag") is not None, (
                f"Version for {key} must have ETag element"
            )

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary


@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestListVersionsOnlyDeleteMarkers:
    """ListObjectVersions on a bucket where all objects are deleted.

    Uses bucket_with_only_delete_markers fixture:
      - dm-only-1: only DeleteMarker (version permanently deleted)
      - dm-only-2: only DeleteMarker (version permanently deleted)
    """

    def test_only_delete_markers_no_versions(
        self, test_bucket, make_request, json_metadata,
        bucket_with_only_delete_markers,
    ):
        """Response contains only <DeleteMarker> entries, no <Version> entries."""
        prefix = bucket_with_only_delete_markers["prefix"]
        query = build_versions_query(prefix=prefix)

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)

        json_metadata["version_count"] = len(parsed["versions"])
        json_metadata["delete_marker_count"] = len(parsed["delete_markers"])

        assert len(parsed["versions"]) == 0, (
            f"Expected 0 versions, got {len(parsed['versions'])}: "
            f"{[v['key'] for v in parsed['versions']]}"
        )
        assert len(parsed["delete_markers"]) == 2, (
            f"Expected 2 delete markers, got {len(parsed['delete_markers'])}"
        )

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    def test_delete_markers_are_all_latest(
        self, test_bucket, make_request, json_metadata,
        bucket_with_only_delete_markers,
    ):
        """All delete markers should have IsLatest=true (they are the only entries)."""
        prefix = bucket_with_only_delete_markers["prefix"]
        query = build_versions_query(prefix=prefix)

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)

        for dm in parsed["delete_markers"]:
            assert dm["is_latest"] == "true", (
                f"Delete marker for {dm['key']} should be latest"
            )

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    def test_delete_markers_have_owner_and_version_id(
        self, test_bucket, make_request, json_metadata,
        bucket_with_only_delete_markers,
    ):
        """Each DeleteMarker must have Key, VersionId, IsLatest, LastModified, Owner."""
        prefix = bucket_with_only_delete_markers["prefix"]
        query = build_versions_query(prefix=prefix)

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)

        root = ET.fromstring(resp.text)
        required_children = ["Key", "VersionId", "IsLatest", "LastModified", "Owner"]

        for dm in root.findall(f"{{{NS}}}DeleteMarker"):
            key = dm.findtext(f"{{{NS}}}Key")
            for child_tag in required_children:
                el = dm.find(f"{{{NS}}}{child_tag}")
                assert el is not None, (
                    f"DeleteMarker for {key} missing required element: {child_tag}"
                )

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    def test_only_markers_with_max_keys_1(
        self, test_bucket, make_request, json_metadata,
        bucket_with_only_delete_markers,
    ):
        """Pagination with max-keys=1 works when only delete markers exist."""
        prefix = bucket_with_only_delete_markers["prefix"]
        query = build_versions_query(prefix=prefix, max_keys="1")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)

        total = len(parsed["versions"]) + len(parsed["delete_markers"])
        json_metadata["total_entries"] = total
        json_metadata["is_truncated"] = parsed["is_truncated"]

        assert total <= 1, f"max-keys=1 should return at most 1 entry, got {total}"
        assert parsed["is_truncated"] == "true", (
            "With 2 delete markers and max-keys=1, should be truncated"
        )

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary
