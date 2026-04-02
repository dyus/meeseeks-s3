"""Quick script to check x-amz-version-id headers from AWS across all versioning modes."""

import os
import uuid
import boto3
import requests as req

from s3_compliance.client import S3ClientFactory
from s3_compliance.signing import sign_request
from s3_compliance.utils import calculate_content_sha256
from tests.put_bucket_versioning.conftest import build_versioning_xml_with_mfa


def main():
    profile = os.getenv("AWS_PROFILE", "default")
    endpoint = os.getenv("S3_ENDPOINT", None)
    region = os.getenv("AWS_REGION", "us-east-1")
    bucket = os.getenv("TEST_BUCKET_NAME", "anon-reverse-s3-test-bucket")

    factory = S3ClientFactory()
    ep_type = "custom" if endpoint else "aws"
    creds = factory.get_credentials(ep_type)
    ep_url = factory.get_endpoint_url(ep_type) or f"https://s3.{region}.amazonaws.com"
    ep_region = factory.get_region(ep_type)

    print(f"Endpoint: {ep_url}")
    print(f"Bucket: {bucket}")
    print(f"Region: {ep_region}")
    print(f"Profile: {profile}")
    print("=" * 80)

    def do_request(method, path, body=b"", headers=None, qp=""):
        hdrs = dict(headers) if headers else {}
        url = f"{ep_url}{path}{qp}"
        signed = sign_request(
            method=method, url=url, headers=hdrs,
            body=body, credentials=creds, region=ep_region,
        )
        func = getattr(req, method.lower())
        return func(url, data=body, headers=signed, verify=True)

    def put_versioning(status):
        body = build_versioning_xml_with_mfa(status, mfa_delete="Disabled")
        resp = do_request("PUT", f"/{bucket}", body=body,
                         headers={"Content-Type": "application/xml"}, qp="?versioning")
        assert resp.status_code == 200, f"PutVersioning({status}) failed: {resp.status_code}"

    def show_vid(label, resp):
        vid = resp.headers.get("x-amz-version-id")
        etag = resp.headers.get("ETag")
        dm = resp.headers.get("x-amz-delete-marker")
        print(f"  {label}: status={resp.status_code}, "
              f"x-amz-version-id={vid!r}, ETag={etag!r}, "
              f"x-amz-delete-marker={dm!r}")

    uid = uuid.uuid4().hex[:8]

    # ---- SUSPENDED (proxy for disabled) ----
    print("\n### Versioning: SUSPENDED")
    put_versioning("Suspended")
    key = f"chk-sus-{uid}"

    r = do_request("PUT", f"/{bucket}/{key}", body=b"suspended-data")
    show_vid("PutObject", r)

    r = do_request("GET", f"/{bucket}/{key}")
    show_vid("GetObject", r)

    r = do_request("DELETE", f"/{bucket}/{key}")
    show_vid("DeleteObject", r)

    # ---- ENABLED ----
    print("\n### Versioning: ENABLED")
    put_versioning("Enabled")
    key = f"chk-en-{uid}"

    r = do_request("PUT", f"/{bucket}/{key}", body=b"v1")
    show_vid("PutObject v1", r)
    vid1 = r.headers.get("x-amz-version-id")

    r = do_request("PUT", f"/{bucket}/{key}", body=b"v2")
    show_vid("PutObject v2", r)

    r = do_request("GET", f"/{bucket}/{key}")
    show_vid("GetObject latest", r)

    if vid1:
        r = do_request("GET", f"/{bucket}/{key}", qp=f"?versionId={vid1}")
        show_vid(f"GetObject vid={vid1[:12]}...", r)

    r = do_request("DELETE", f"/{bucket}/{key}")
    show_vid("DeleteObject (create DM)", r)
    dm_vid = r.headers.get("x-amz-version-id")

    r = do_request("GET", f"/{bucket}/{key}")
    show_vid("GetObject after DM", r)

    # ---- SUSPENDED after ENABLED ----
    print("\n### Versioning: SUSPENDED (after Enabled)")
    put_versioning("Suspended")
    key2 = f"chk-sus2-{uid}"

    r = do_request("PUT", f"/{bucket}/{key2}", body=b"sus-after-en")
    show_vid("PutObject", r)

    r = do_request("GET", f"/{bucket}/{key2}")
    show_vid("GetObject latest", r)

    r = do_request("DELETE", f"/{bucket}/{key2}")
    show_vid("DeleteObject", r)

    print("\n" + "=" * 80)
    print("Done.")


if __name__ == "__main__":
    main()
