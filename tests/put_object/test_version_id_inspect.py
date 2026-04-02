"""Inspect x-amz-version-id headers across all versioning modes.

Prints actual header values for manual verification.
"""

import uuid
import pytest

from tests.put_bucket_versioning.conftest import build_versioning_xml_with_mfa


def _put_versioning(make_request, bucket, status):
    body = build_versioning_xml_with_mfa(status, mfa_delete="Disabled")
    resp = make_request("PUT", f"/{bucket}", body=body,
                       headers={"Content-Type": "application/xml"}, query_params="?versioning")
    sc = resp.aws.status_code if hasattr(resp, "comparison") else resp.status_code
    assert sc == 200, f"PutVersioning({status}) failed: {sc}"


def _sc(resp):
    return resp.aws.status_code if hasattr(resp, "comparison") else resp.status_code

def _h(resp):
    return dict(resp.aws.headers) if hasattr(resp, "comparison") else dict(resp.headers)


@pytest.mark.s3_handler("PutObject")
class TestVersionIdInspect:

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_inspect_all_modes(self, test_bucket, make_request):
        uid = uuid.uuid4().hex[:8]

        results = []

        for mode in ["Suspended", "Enabled"]:
            _put_versioning(make_request, test_bucket, mode)

            # PutObject
            key = f"inspect-{mode.lower()}-{uid}"
            r = make_request("PUT", f"/{test_bucket}/{key}", body=b"data-" + mode.encode())
            h = _h(r)
            results.append({
                "mode": mode, "op": "PutObject",
                "status": _sc(r),
                "x-amz-version-id": h.get("x-amz-version-id"),
                "ETag": h.get("ETag", h.get("etag")),
                "x-amz-delete-marker": h.get("x-amz-delete-marker"),
            })

            # GetObject
            r = make_request("GET", f"/{test_bucket}/{key}")
            h = _h(r)
            results.append({
                "mode": mode, "op": "GetObject",
                "status": _sc(r),
                "x-amz-version-id": h.get("x-amz-version-id"),
                "ETag": h.get("ETag", h.get("etag")),
                "x-amz-delete-marker": h.get("x-amz-delete-marker"),
            })

            # DeleteObject
            r = make_request("DELETE", f"/{test_bucket}/{key}")
            h = _h(r)
            results.append({
                "mode": mode, "op": "DeleteObject",
                "status": _sc(r),
                "x-amz-version-id": h.get("x-amz-version-id"),
                "ETag": h.get("ETag", h.get("etag")),
                "x-amz-delete-marker": h.get("x-amz-delete-marker"),
            })

        # Suspended after Enabled
        _put_versioning(make_request, test_bucket, "Suspended")
        key = f"inspect-sus2-{uid}"
        r = make_request("PUT", f"/{test_bucket}/{key}", body=b"sus-after-en")
        h = _h(r)
        results.append({
            "mode": "Suspended(after)", "op": "PutObject",
            "status": _sc(r),
            "x-amz-version-id": h.get("x-amz-version-id"),
            "ETag": h.get("ETag", h.get("etag")),
            "x-amz-delete-marker": h.get("x-amz-delete-marker"),
        })

        r = make_request("GET", f"/{test_bucket}/{key}")
        h = _h(r)
        results.append({
            "mode": "Suspended(after)", "op": "GetObject",
            "status": _sc(r),
            "x-amz-version-id": h.get("x-amz-version-id"),
            "ETag": h.get("ETag", h.get("etag")),
            "x-amz-delete-marker": h.get("x-amz-delete-marker"),
        })

        r = make_request("DELETE", f"/{test_bucket}/{key}")
        h = _h(r)
        results.append({
            "mode": "Suspended(after)", "op": "DeleteObject",
            "status": _sc(r),
            "x-amz-version-id": h.get("x-amz-version-id"),
            "ETag": h.get("ETag", h.get("etag")),
            "x-amz-delete-marker": h.get("x-amz-delete-marker"),
        })

        # Print table
        print("\n" + "=" * 100)
        print(f"{'Mode':<20} {'Op':<15} {'Status':<7} {'x-amz-version-id':<40} {'ETag':<36} {'delete-marker'}")
        print("-" * 100)
        for r in results:
            print(f"{r['mode']:<20} {r['op']:<15} {r['status']:<7} "
                  f"{str(r['x-amz-version-id']):<40} "
                  f"{str(r['ETag']):<36} {r['x-amz-delete-marker']}")
        print("=" * 100)
