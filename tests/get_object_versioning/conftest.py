"""Shared fixtures for GetObject versioning tests."""

import uuid

import pytest

from tests.put_bucket_versioning.conftest import build_versioning_xml_with_mfa


def _put_versioning(make_request, bucket, status):
    """Set bucket versioning status."""
    body = build_versioning_xml_with_mfa(status, mfa_delete="Disabled")
    headers = {"Content-Type": "application/xml"}
    resp = make_request("PUT", f"/{bucket}", body=body, headers=headers, query_params="?versioning")
    sc = resp.aws.status_code if hasattr(resp, "comparison") else resp.status_code
    assert sc == 200, f"PutBucketVersioning({status}) failed: {sc}"
    return resp


def _put_object(make_request, bucket, key, body_bytes):
    """Upload object and return response."""
    return make_request("PUT", f"/{bucket}/{key}", body=body_bytes)


def _delete_object(make_request, bucket, key, version_id=None):
    """Delete object (creates delete marker in versioned bucket)."""
    qp = "?versionId=" + version_id if version_id else ""
    return make_request("DELETE", f"/{bucket}/{key}", query_params=qp)


def _get_status(resp):
    """Extract status code from single or comparison response."""
    if hasattr(resp, "comparison"):
        return resp.aws.status_code
    return resp.status_code


def _get_headers(resp):
    """Extract response headers from single or comparison response."""
    if hasattr(resp, "comparison"):
        return dict(resp.aws.headers)
    return dict(resp.headers)


def _get_text(resp):
    """Extract response text from single or comparison response."""
    if hasattr(resp, "comparison"):
        return resp.aws.text
    return resp.text


@pytest.fixture(scope="module")
def unique_prefix():
    """Unique prefix for test keys to avoid collisions."""
    return f"gov-{uuid.uuid4().hex[:8]}"
