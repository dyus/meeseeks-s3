"""Shared utilities and fixtures for ListObjectVersions tests."""

import urllib.parse
import uuid

import pytest


def build_versions_query(
    key_marker: str = None,
    version_id_marker: str = None,
    max_keys: str = None,
    prefix: str = None,
    delimiter: str = None,
    encoding_type: str = None,
) -> str:
    """Build query string for ListObjectVersions.

    All parameters are optional. Returns query string starting with '?versions'.
    Values are percent-encoded for URL safety (non-ASCII characters, spaces, etc.).
    Empty strings are preserved as-is (e.g., key-marker= for empty value tests).
    """
    parts = ["versions"]
    if delimiter is not None:
        parts.append(f"delimiter={_encode_value(delimiter)}")
    if encoding_type is not None:
        parts.append(f"encoding-type={_encode_value(encoding_type)}")
    if key_marker is not None:
        parts.append(f"key-marker={_encode_value(key_marker)}")
    if max_keys is not None:
        parts.append(f"max-keys={_encode_value(max_keys)}")
    if prefix is not None:
        parts.append(f"prefix={_encode_value(prefix)}")
    if version_id_marker is not None:
        parts.append(f"version-id-marker={_encode_value(version_id_marker)}")
    return "?" + "&".join(parts)


def _encode_value(value: str) -> str:
    """Percent-encode a query parameter value.

    Preserves unreserved characters (RFC 3986) and encodes everything else.
    Empty strings are returned as-is.
    """
    if not value:
        return value
    return urllib.parse.quote(value, safe="-._~")


@pytest.fixture(scope="module")
def versioned_objects_prefix(test_bucket):
    """Unique prefix for versioned test objects to avoid collisions."""
    return f"lov-test-{uuid.uuid4().hex[:8]}/"


@pytest.fixture(scope="module")
def bucket_with_versions_and_markers(
    request, setup_client, test_bucket, setup_test_bucket, versioned_objects_prefix,
):
    """Pre-populate bucket with versioned objects AND delete markers.

    Creates:
      - {prefix}obj-alive: 2 versions (v1, v2) — latest is Version
      - {prefix}obj-deleted: 1 version + delete marker — latest is DeleteMarker
      - {prefix}obj-revived: 1 version + delete marker + 1 version — latest is Version

    Yields dict with keys, version_ids, and delete_marker info.
    """
    prefix = versioned_objects_prefix

    # Enable versioning
    setup_client.put_bucket_versioning(
        Bucket=test_bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )

    created = {"prefix": prefix, "keys": {}}

    # obj-alive: two versions, no delete marker
    key_alive = f"{prefix}obj-alive"
    r1 = setup_client.put_object(Bucket=test_bucket, Key=key_alive, Body=b"v1")
    r2 = setup_client.put_object(Bucket=test_bucket, Key=key_alive, Body=b"v2")
    created["keys"]["alive"] = {
        "key": key_alive,
        "version_ids": [r1.get("VersionId"), r2.get("VersionId")],
    }

    # obj-deleted: one version, then delete → creates delete marker as latest
    key_deleted = f"{prefix}obj-deleted"
    r3 = setup_client.put_object(Bucket=test_bucket, Key=key_deleted, Body=b"v1")
    r4 = setup_client.delete_object(Bucket=test_bucket, Key=key_deleted)
    created["keys"]["deleted"] = {
        "key": key_deleted,
        "version_ids": [r3.get("VersionId")],
        "delete_marker_id": r4.get("VersionId"),
    }

    # obj-revived: version → delete → version again
    key_revived = f"{prefix}obj-revived"
    r5 = setup_client.put_object(Bucket=test_bucket, Key=key_revived, Body=b"v1")
    r6 = setup_client.delete_object(Bucket=test_bucket, Key=key_revived)
    r7 = setup_client.put_object(Bucket=test_bucket, Key=key_revived, Body=b"v2-revived")
    created["keys"]["revived"] = {
        "key": key_revived,
        "version_ids": [r5.get("VersionId"), r7.get("VersionId")],
        "delete_marker_id": r6.get("VersionId"),
    }

    yield created

    # Cleanup: permanently delete all versions and markers
    paginator = setup_client.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=test_bucket, Prefix=prefix):
        for v in page.get("Versions", []):
            try:
                setup_client.delete_object(
                    Bucket=test_bucket, Key=v["Key"], VersionId=v["VersionId"],
                )
            except Exception:
                pass
        for dm in page.get("DeleteMarkers", []):
            try:
                setup_client.delete_object(
                    Bucket=test_bucket, Key=dm["Key"], VersionId=dm["VersionId"],
                )
            except Exception:
                pass


@pytest.fixture(scope="module")
def bucket_with_only_delete_markers(
    request, setup_client, test_bucket, setup_test_bucket,
):
    """Pre-populate bucket with ONLY delete markers (no live versions visible in ListObjects).

    Creates:
      - {prefix}dm-only-1: 1 version + delete (permanently delete the version, keep marker)
      - {prefix}dm-only-2: 1 version + delete (permanently delete the version, keep marker)

    All objects have delete markers as latest; the underlying versions are
    permanently removed so only DeleteMarker entries appear in ListObjectVersions.

    Yields dict with keys and marker info.
    """
    prefix = f"lov-dm-only-{uuid.uuid4().hex[:8]}/"

    # Enable versioning
    setup_client.put_bucket_versioning(
        Bucket=test_bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )

    created = {"prefix": prefix, "keys": {}}

    for i, name in enumerate(["dm-only-1", "dm-only-2"], 1):
        key = f"{prefix}{name}"
        # Create version, then delete to get a delete marker
        r_put = setup_client.put_object(Bucket=test_bucket, Key=key, Body=f"data-{i}".encode())
        version_id = r_put.get("VersionId")
        r_del = setup_client.delete_object(Bucket=test_bucket, Key=key)
        # Permanently delete the underlying version, leaving only the delete marker
        setup_client.delete_object(Bucket=test_bucket, Key=key, VersionId=version_id)
        created["keys"][name] = {
            "key": key,
            "delete_marker_id": r_del.get("VersionId"),
        }

    yield created

    # Cleanup
    paginator = setup_client.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=test_bucket, Prefix=prefix):
        for v in page.get("Versions", []):
            try:
                setup_client.delete_object(
                    Bucket=test_bucket, Key=v["Key"], VersionId=v["VersionId"],
                )
            except Exception:
                pass
        for dm in page.get("DeleteMarkers", []):
            try:
                setup_client.delete_object(
                    Bucket=test_bucket, Key=dm["Key"], VersionId=dm["VersionId"],
                )
            except Exception:
                pass
