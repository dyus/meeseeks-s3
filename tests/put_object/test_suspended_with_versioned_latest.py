"""Check: GetObject when latest version was created while Enabled, but bucket is now Suspended.

Does AWS return x-amz-version-id in this case?
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


def _sc(r):
    return r.aws.status_code if hasattr(r, "comparison") else r.status_code

def _h(r):
    return dict(r.aws.headers) if hasattr(r, "comparison") else dict(r.headers)


@pytest.mark.s3_handler("GetObject")
class TestSuspendedWithVersionedLatest:

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_get_versioned_obj_after_suspend(self, test_bucket, make_request):
        """Enable → PUT (creates versioned obj) → Suspend → GET latest.

        Question: does GET return x-amz-version-id with the real version-id
        or 'null' or nothing?
        """
        uid = uuid.uuid4().hex[:8]
        key = f"sus-latest-{uid}"

        # Enable versioning
        _put_versioning(make_request, test_bucket, "Enabled")

        # PUT object (versioned — gets real version-id)
        put_resp = make_request("PUT", f"/{test_bucket}/{key}", body=b"versioned-data")
        put_h = _h(put_resp)
        put_vid = put_h.get("x-amz-version-id")
        print(f"\n--- PutObject (Enabled) ---")
        print(f"  status={_sc(put_resp)}")
        print(f"  x-amz-version-id={put_vid!r}")
        print(f"  ETag={put_h.get('ETag')!r}")

        # Suspend versioning
        _put_versioning(make_request, test_bucket, "Suspended")

        # GET latest — no versionId param
        get_resp = make_request("GET", f"/{test_bucket}/{key}")
        get_h = _h(get_resp)
        get_vid = get_h.get("x-amz-version-id")
        print(f"\n--- GetObject latest (Suspended, but obj was created while Enabled) ---")
        print(f"  status={_sc(get_resp)}")
        print(f"  x-amz-version-id={get_vid!r}")
        print(f"  ETag={get_h.get('ETag')!r}")

        # GET with explicit versionId
        if put_vid:
            get2_resp = make_request("GET", f"/{test_bucket}/{key}",
                                    query_params=f"?versionId={put_vid}")
            get2_h = _h(get2_resp)
            print(f"\n--- GetObject ?versionId={put_vid} (Suspended) ---")
            print(f"  status={_sc(get2_resp)}")
            print(f"  x-amz-version-id={get2_h.get('x-amz-version-id')!r}")

        # Now PUT again (creates null version, overwrites null slot)
        put2_resp = make_request("PUT", f"/{test_bucket}/{key}", body=b"null-overwrite")
        put2_h = _h(put2_resp)
        print(f"\n--- PutObject (Suspended — null version) ---")
        print(f"  status={_sc(put2_resp)}")
        print(f"  x-amz-version-id={put2_h.get('x-amz-version-id')!r}")

        # GET latest — should now be null version
        get3_resp = make_request("GET", f"/{test_bucket}/{key}")
        get3_h = _h(get3_resp)
        print(f"\n--- GetObject latest (after null overwrite) ---")
        print(f"  status={_sc(get3_resp)}")
        print(f"  x-amz-version-id={get3_h.get('x-amz-version-id')!r}")
        print(f"  body={get3_resp.aws.content if hasattr(get3_resp, 'comparison') else get3_resp.content}")

        # Old versioned version should still be accessible
        if put_vid:
            get4_resp = make_request("GET", f"/{test_bucket}/{key}",
                                    query_params=f"?versionId={put_vid}")
            get4_h = _h(get4_resp)
            print(f"\n--- GetObject ?versionId={put_vid} (after null overwrite) ---")
            print(f"  status={_sc(get4_resp)}")
            print(f"  x-amz-version-id={get4_h.get('x-amz-version-id')!r}")
            print(f"  body={get4_resp.aws.content if hasattr(get4_resp, 'comparison') else get4_resp.content}")
