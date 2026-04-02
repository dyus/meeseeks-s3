"""Compare GET vs HEAD behavior on DeleteMarker — AWS only."""

import uuid
import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml_with_mfa


def _put_versioning(make_request, bucket, status):
    body = build_versioning_xml_with_mfa(status, mfa_delete="Disabled")
    resp = make_request("PUT", f"/{bucket}", body=body,
                       headers={"Content-Type": "application/xml"}, query_params="?versioning")
    sc = resp.aws.status_code if hasattr(resp, "comparison") else resp.status_code
    assert sc == 200

def _sc(r):
    return r.aws.status_code if hasattr(r, "comparison") else r.status_code

def _h(r):
    return r.aws.headers if hasattr(r, "comparison") else r.headers

def _text(r):
    return r.aws.text if hasattr(r, "comparison") else r.text


@pytest.mark.s3_handler("GetObject")
class TestHeadVsGetDeleteMarker:

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_compare_get_head_on_delete_marker(self, test_bucket, make_request):
        uid = uuid.uuid4().hex[:8]
        key = f"dm-compare-{uid}"

        _put_versioning(make_request, test_bucket, "Enabled")

        # Create object then delete (creates DM)
        make_request("PUT", f"/{test_bucket}/{key}", body=b"data")
        del_resp = make_request("DELETE", f"/{test_bucket}/{key}")
        dm_vid = _h(del_resp).get("x-amz-version-id")

        print(f"\nDeleteMarker version-id: {dm_vid}")

        # --- GET without versionId (latest = DM) ---
        get_resp = make_request("GET", f"/{test_bucket}/{key}")
        print(f"\n=== GET /{key} (latest=DM) ===")
        print(f"  Status: {_sc(get_resp)}")
        print(f"  Headers:")
        for k, v in _h(get_resp).items():
            print(f"    {k}: {v}")
        print(f"  Body: {_text(get_resp)[:300]}")

        # --- HEAD without versionId (latest = DM) ---
        head_resp = make_request("HEAD", f"/{test_bucket}/{key}")
        print(f"\n=== HEAD /{key} (latest=DM) ===")
        print(f"  Status: {_sc(head_resp)}")
        print(f"  Headers:")
        for k, v in _h(head_resp).items():
            print(f"    {k}: {v}")

        # --- GET with versionId = DM ---
        if dm_vid:
            get_dm_resp = make_request("GET", f"/{test_bucket}/{key}",
                                       query_params=f"?versionId={dm_vid}")
            print(f"\n=== GET /{key}?versionId={dm_vid} ===")
            print(f"  Status: {_sc(get_dm_resp)}")
            print(f"  Headers:")
            for k, v in _h(get_dm_resp).items():
                print(f"    {k}: {v}")
            print(f"  Body: {_text(get_dm_resp)[:300]}")

            # --- HEAD with versionId = DM ---
            head_dm_resp = make_request("HEAD", f"/{test_bucket}/{key}",
                                        query_params=f"?versionId={dm_vid}")
            print(f"\n=== HEAD /{key}?versionId={dm_vid} ===")
            print(f"  Status: {_sc(head_dm_resp)}")
            print(f"  Headers:")
            for k, v in _h(head_dm_resp).items():
                print(f"    {k}: {v}")
