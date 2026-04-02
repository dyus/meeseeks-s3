"""Tests for ListObjectVersions successful scenarios.

Verifies correct behavior for valid requests: pagination with key-marker
and version-id-marker, delimiter handling with NextKeyMarker, prefix
filtering, and empty/absent query parameter behavior.

Based on empirical AWS testing from listobj/2/test_list_object_versions_python.md.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import xml.etree.ElementTree as ET

import pytest

from s3_compliance.xml_utils import extract_error_info

from .conftest import build_versions_query


NS = "http://s3.amazonaws.com/doc/2006-03-01/"


def _parse_list_versions(text):
    """Parse ListVersionsResult XML, return dict with key fields."""
    root = ET.fromstring(text)
    result = {
        "name": _find_text(root, "Name"),
        "prefix": _find_text(root, "Prefix"),
        "key_marker": _find_text(root, "KeyMarker"),
        "version_id_marker": _find_text(root, "VersionIdMarker"),
        "max_keys": _find_text(root, "MaxKeys"),
        "is_truncated": _find_text(root, "IsTruncated"),
        "next_key_marker": _find_text(root, "NextKeyMarker"),
        "next_version_id_marker": _find_text(root, "NextVersionIdMarker"),
        "delimiter": _find_text(root, "Delimiter"),
        "versions": [],
        "delete_markers": [],
        "common_prefixes": [],
    }
    for v in root.findall(f"{{{NS}}}Version"):
        result["versions"].append({
            "key": _find_text(v, "Key"),
            "version_id": _find_text(v, "VersionId"),
            "is_latest": _find_text(v, "IsLatest"),
        })
    for dm in root.findall(f"{{{NS}}}DeleteMarker"):
        result["delete_markers"].append({
            "key": _find_text(dm, "Key"),
            "version_id": _find_text(dm, "VersionId"),
            "is_latest": _find_text(dm, "IsLatest"),
        })
    for cp in root.findall(f"{{{NS}}}CommonPrefixes"):
        prefix_el = cp.find(f"{{{NS}}}Prefix")
        if prefix_el is not None and prefix_el.text:
            result["common_prefixes"].append(prefix_el.text)
    return result


def _find_text(element, tag):
    """Find text of a child element with S3 namespace."""
    el = element.find(f"{{{NS}}}{tag}")
    return el.text if el is not None else None


def _get_response(response):
    """Get the response object (handles both single and comparison modes)."""
    if hasattr(response, "comparison"):
        return response.aws
    return response


def _assert_200(response):
    """Assert 200 for both single and comparison modes."""
    if hasattr(response, "comparison"):
        assert response.aws.status_code == 200, (
            f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
        )
    else:
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text[:200]}"
        )


@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestListObjectVersionsBasicListing:
    """Test basic ListObjectVersions listing."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_all_versions(
        self, test_bucket, make_request, json_metadata,
    ):
        """GET ?versions with no extra params returns 200 with all versions."""
        query = build_versions_query()

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["name"] = parsed["name"]
        json_metadata["max_keys"] = parsed["max_keys"]
        json_metadata["is_truncated"] = parsed["is_truncated"]
        json_metadata["version_count"] = len(parsed["versions"])
        json_metadata["delete_marker_count"] = len(parsed["delete_markers"])

        assert parsed["name"] == test_bucket
        assert parsed["max_keys"] == "1000"
        assert parsed["is_truncated"] == "false"

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_with_max_keys_zero(
        self, test_bucket, make_request, json_metadata,
    ):
        """max-keys=0 returns 200 with no versions."""
        query = build_versions_query(max_keys="0")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["max_keys"] = parsed["max_keys"]
        json_metadata["version_count"] = len(parsed["versions"])

        assert parsed["max_keys"] == "0"
        assert len(parsed["versions"]) == 0

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_list_with_max_keys_1(
        self, test_bucket, make_request, json_metadata,
    ):
        """max-keys=1 returns at most 1 entry."""
        query = build_versions_query(max_keys="1")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["max_keys"] = parsed["max_keys"]
        total = len(parsed["versions"]) + len(parsed["delete_markers"])
        json_metadata["total_entries"] = total

        assert parsed["max_keys"] == "1"
        assert total <= 1

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary


@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestListObjectVersionsKeyMarkerPagination:
    """Test pagination with key-marker and version-id-marker."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_key_marker_nonexistent_key(
        self, test_bucket, make_request, json_metadata,
    ):
        """key-marker with non-existent key returns versions after that key (200)."""
        query = build_versions_query(key_marker="zzz-nonexistent", max_keys="5")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["key_marker"] = parsed["key_marker"]
        json_metadata["version_count"] = len(parsed["versions"])

        assert parsed["key_marker"] == "zzz-nonexistent"

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_key_marker_without_version_id_marker(
        self, test_bucket, make_request, json_metadata,
    ):
        """key-marker alone (no version-id-marker) returns 200."""
        query = build_versions_query(key_marker="ab", max_keys="1")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["key_marker"] = parsed["key_marker"]

        assert parsed["key_marker"] == "ab"
        assert parsed["version_id_marker"] in (None, "")

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary


@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestListObjectVersionsDelimiter:
    """Test delimiter handling and CommonPrefixes in ListObjectVersions."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delimiter_returns_common_prefixes(
        self, test_bucket, make_request, json_metadata,
    ):
        """delimiter=/ groups keys into CommonPrefixes."""
        query = build_versions_query(delimiter="/", max_keys="1000")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["delimiter"] = parsed["delimiter"]
        json_metadata["common_prefixes"] = parsed["common_prefixes"]
        json_metadata["version_count"] = len(parsed["versions"])

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_delimiter_truncated_next_key_marker(
        self, test_bucket, make_request, json_metadata,
    ):
        """Truncated listing with delimiter provides NextKeyMarker."""
        query = build_versions_query(delimiter="/", max_keys="1")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["is_truncated"] = parsed["is_truncated"]
        json_metadata["next_key_marker"] = parsed["next_key_marker"]

        if parsed["is_truncated"] == "true":
            assert parsed["next_key_marker"] is not None, (
                "NextKeyMarker must be present when IsTruncated=true"
            )

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary


@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestListObjectVersionsEmptyParams:
    """Test behavior when query parameters are present but empty.

    Based on empirical results from listobj/2/:
      - delimiter="" → same as absent (200)
      - prefix="" → same as absent (200)
      - encoding-type="" → 400 InvalidArgument
      - max-keys="" → 200, treated as default 1000
      - version-id-marker="" (with key-marker) → 400 "cannot be empty"
    """

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_delimiter_same_as_absent(
        self, test_bucket, make_request, json_metadata,
    ):
        """delimiter="" is treated same as no delimiter (200)."""
        query = build_versions_query(delimiter="", max_keys="5")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["delimiter"] = parsed.get("delimiter")

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_prefix_same_as_absent(
        self, test_bucket, make_request, json_metadata,
    ):
        """prefix="" is treated same as no prefix (200)."""
        query = build_versions_query(prefix="", max_keys="5")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["prefix"] = parsed["prefix"]

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_encoding_type_returns_400(
        self, test_bucket, make_request, json_metadata,
    ):
        """encoding-type="" returns 400 InvalidArgument (not treated as absent).

        Error: 'Invalid Encoding Method specified in Request'
        """
        query = build_versions_query(encoding_type="", max_keys="5")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_max_keys_treated_as_default(
        self, test_bucket, make_request, json_metadata,
    ):
        """max-keys="" returns 200 and uses default value 1000.

        AWS treats empty max-keys as absent (default 1000), NOT as invalid.
        """
        query = build_versions_query(max_keys="")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["max_keys"] = parsed["max_keys"]

        assert parsed["max_keys"] == "1000", (
            f"Empty max-keys should default to 1000, got {parsed['max_keys']}"
        )

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_version_id_marker_returns_400(
        self, test_bucket, make_request, json_metadata,
    ):
        """version-id-marker="" (empty string) with key-marker returns 400.

        Error: 'A version-id marker cannot be empty.'
        Note: this is DIFFERENT from the 'cannot be specified without a key marker'
        error. Empty string is a distinct error from absent parameter.
        """
        query = build_versions_query(
            key_marker="some-key",
            version_id_marker="",
            max_keys="1",
        )

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "cannot be empty" in error_msg.lower(), (
                f"Expected 'cannot be empty' error, got: {error_msg}"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "cannot be empty" in error_msg.lower(), (
                f"Expected 'cannot be empty' error, got: {error_msg}"
            )


@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestListObjectVersionsVersionIdValidation:
    """Test version-id-marker format validation.

    AWS validates version-id format. Both random strings and version-id-like
    strings (correct length/charset but non-existent) are rejected.
    """

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_version_id_random_string(
        self, test_bucket, make_request, json_metadata,
    ):
        """Random string version-id-marker → 400 'Invalid version id specified'."""
        query = build_versions_query(
            key_marker="some-key",
            version_id_marker="nonexistent-version-id-12345",
            max_keys="1",
        )

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "invalid version id" in error_msg.lower()
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "invalid version id" in error_msg.lower()

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_version_id_similar_format(
        self, test_bucket, make_request, json_metadata,
    ):
        """Version-id-like string (correct length/charset) but non-existent → 400.

        Even if the format looks like a real version-id (32 chars, base64-like),
        AWS rejects it if it doesn't exist in the bucket.
        """
        query = build_versions_query(
            key_marker="some-key",
            version_id_marker="Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R",
            max_keys="1",
        )

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_version_id_null_is_valid(
        self, test_bucket, make_request, json_metadata,
    ):
        """version-id-marker='null' with key-marker returns 200.

        'null' is a special version-id for objects created before versioning.
        """
        query = build_versions_query(
            key_marker="some-key",
            version_id_marker="null",
            max_keys="1",
        )

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["key_marker"] = parsed["key_marker"]
        json_metadata["version_id_marker"] = parsed["version_id_marker"]

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary


@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestListObjectVersionsVersionIdNullPagination:
    """Test that version-id-marker='null' works as a pagination marker.

    'null' is a special version-id used for objects created before versioning
    was enabled. AWS always accepts it and uses it for pagination — objects
    after the key-marker are returned normally.

    Based on empirical AWS testing: vid='null' is NOT validated against the
    database. It is always accepted regardless of whether the key exists or
    has a 'null' version.
    """

    def test_vid_null_returns_objects_after_key_marker(
        self, test_bucket, make_request, json_metadata,
        bucket_with_versions_and_markers,
    ):
        """key-marker + version-id-marker=null returns versions after key-marker."""
        data = bucket_with_versions_and_markers
        prefix = data["prefix"]
        # key-marker = obj-alive, vid=null → should return obj-deleted and obj-revived
        key_alive = data["keys"]["alive"]["key"]

        query = build_versions_query(
            key_marker=key_alive,
            version_id_marker="null",
            prefix=prefix,
        )

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["key_marker"] = parsed["key_marker"]
        json_metadata["version_id_marker"] = parsed["version_id_marker"]
        json_metadata["version_count"] = len(parsed["versions"])
        json_metadata["delete_marker_count"] = len(parsed["delete_markers"])

        assert parsed["key_marker"] == key_alive
        assert parsed["version_id_marker"] == "null"

        # Should have versions/markers for obj-deleted and obj-revived
        all_keys = {v["key"] for v in parsed["versions"]}
        all_keys.update(dm["key"] for dm in parsed["delete_markers"])
        assert key_alive not in all_keys, (
            "obj-alive should NOT appear — it's the key-marker"
        )
        assert len(parsed["versions"]) + len(parsed["delete_markers"]) > 0, (
            "Should return versions after key-marker"
        )

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    def test_vid_null_with_last_key_returns_empty(
        self, test_bucket, make_request, json_metadata,
        bucket_with_versions_and_markers,
    ):
        """key-marker=last-key + version-id-marker=null returns empty listing."""
        data = bucket_with_versions_and_markers
        prefix = data["prefix"]
        # obj-revived is the last key alphabetically
        key_revived = data["keys"]["revived"]["key"]

        query = build_versions_query(
            key_marker=key_revived,
            version_id_marker="null",
            prefix=prefix,
        )

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["key_marker"] = parsed["key_marker"]
        json_metadata["version_count"] = len(parsed["versions"])
        json_metadata["delete_marker_count"] = len(parsed["delete_markers"])

        assert parsed["key_marker"] == key_revived
        assert parsed["version_id_marker"] == "null"
        assert len(parsed["versions"]) == 0, "No versions after last key"
        assert len(parsed["delete_markers"]) == 0, "No delete markers after last key"

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_vid_null_with_nonexistent_key(
        self, test_bucket, make_request, json_metadata,
    ):
        """key-marker=nonexistent + version-id-marker=null returns 200.

        AWS does not validate key-marker existence. 'null' is always valid.
        """
        query = build_versions_query(
            key_marker="zzz-nonexistent-key",
            version_id_marker="null",
            max_keys="5",
        )

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["key_marker"] = parsed["key_marker"]
        json_metadata["version_id_marker"] = parsed["version_id_marker"]

        assert parsed["key_marker"] == "zzz-nonexistent-key"
        assert parsed["version_id_marker"] == "null"

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary


@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestListObjectVersionsPrefixFiltering:
    """Test prefix parameter filtering."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_prefix_filters_results(
        self, test_bucket, make_request, json_metadata,
    ):
        """prefix parameter filters versions to matching keys only."""
        query = build_versions_query(prefix="nonexistent-prefix/", max_keys="100")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)
        resp = _get_response(response)
        parsed = _parse_list_versions(resp.text)
        json_metadata["prefix"] = parsed["prefix"]
        json_metadata["version_count"] = len(parsed["versions"])

        assert parsed["prefix"] == "nonexistent-prefix/"
        assert len(parsed["versions"]) == 0

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_encoding_type_url(
        self, test_bucket, make_request, json_metadata,
    ):
        """encoding-type=url returns 200 with URL-encoded keys."""
        query = build_versions_query(encoding_type="url", max_keys="5")

        response = make_request("GET", f"/{test_bucket}", query_params=query)

        _assert_200(response)

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary
