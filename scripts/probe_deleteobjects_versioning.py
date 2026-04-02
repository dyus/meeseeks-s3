#!/usr/bin/env python3
"""Probe DeleteObjects versioning behavior on real AWS S3.

Sends requests and records raw XML responses for reverse engineering.
"""

import hashlib
import base64
import uuid
import time
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import boto3
import requests
from s3_compliance.signing import sign_request
from s3_compliance.utils import calculate_content_md5, calculate_content_sha256

BUCKET = os.getenv("TEST_BUCKET_NAME", "anon-reverse-s3-test-bucket")
PROFILE = os.getenv("AWS_PROFILE", "default")
REGION = os.getenv("AWS_REGION", "us-east-1")
ENDPOINT = os.getenv("AWS_S3_ENDPOINT", "https://s3.us-east-1.amazonaws.com")

session = boto3.Session(profile_name=PROFILE, region_name=REGION)
s3 = session.client("s3", region_name=REGION)
creds = session.get_credentials().get_frozen_credentials()

RESULTS = []


def uid():
    return uuid.uuid4().hex[:8]


def put_versioning(status):
    s3.put_bucket_versioning(
        Bucket=BUCKET,
        VersioningConfiguration={"Status": status},
    )
    time.sleep(0.5)


def get_versioning():
    r = s3.get_bucket_versioning(Bucket=BUCKET)
    return r.get("Status", "Disabled")


def put_object(key, body=b"data"):
    r = s3.put_object(Bucket=BUCKET, Key=key, Body=body)
    return r.get("VersionId")


def delete_objects_raw(objects_xml, quiet=False):
    """Send raw DeleteObjects POST and return response text."""
    quiet_xml = "<Quiet>true</Quiet>" if quiet else ""
    xml_body = f'''<?xml version="1.0" encoding="UTF-8"?>
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
{quiet_xml}
{objects_xml}
</Delete>'''

    body = xml_body.encode("utf-8")
    url = f"{ENDPOINT}/{BUCKET}?delete"
    md5 = base64.b64encode(hashlib.md5(body).digest()).decode()
    sha256 = calculate_content_sha256(body)

    headers = {
        "Content-Type": "application/xml",
        "Content-MD5": md5,
        "Content-Length": str(len(body)),
        "x-amz-content-sha256": sha256,
    }

    signed = sign_request(
        method="POST", url=url, headers=headers, body=body,
        credentials=creds, region=REGION,
    )

    resp = requests.post(url, data=body, headers=signed, verify=True)
    return resp.status_code, resp.text


def obj_xml(key, version_id=None):
    vid = f"\n        <VersionId>{version_id}</VersionId>" if version_id else ""
    return f"    <Object>\n        <Key>{key}</Key>{vid}\n    </Object>"


def record(test_id, description, status, body):
    RESULTS.append((test_id, description, status, body))
    print(f"\n{'='*70}")
    print(f"## {test_id}: {description}")
    print(f"Status: {status}")
    print(body)


def cleanup(*keys):
    """Best-effort cleanup of all versions of given keys."""
    for key in keys:
        try:
            versions = s3.list_object_versions(Bucket=BUCKET, Prefix=key)
            for v in versions.get("Versions", []):
                if v["Key"] == key:
                    s3.delete_object(Bucket=BUCKET, Key=key, VersionId=v["VersionId"])
            for dm in versions.get("DeleteMarkers", []):
                if dm["Key"] == key:
                    s3.delete_object(Bucket=BUCKET, Key=key, VersionId=dm["VersionId"])
        except Exception:
            pass


# ============================================================================
# A. Versioning Disabled
# ============================================================================

def test_a_disabled():
    put_versioning("Suspended")  # can't truly disable, but Suspended with no versions acts similar
    # Actually for "disabled" we need a bucket that was never versioned.
    # We'll use Suspended as closest equivalent since bucket was already versioned.
    # Note: truly disabled = never had versioning enabled.

    k1 = f"delobj-a1-{uid()}"
    k2 = f"delobj-a2-{uid()}"
    k3 = f"delobj-a3a-{uid()}"
    k4 = f"delobj-a3b-{uid()}"
    k5 = f"delobj-a4-{uid()}"

    # A1: delete existing object
    put_object(k1, b"a1-data")
    sc, body = delete_objects_raw(obj_xml(k1))
    record("A1", "Suspended: delete existing object (no versionId)", sc, body)

    # A2: delete nonexistent object
    sc, body = delete_objects_raw(obj_xml(k2))
    record("A2", "Suspended-as-disabled: delete nonexistent object", sc, body)

    # A3: delete two different objects
    put_object(k3, b"a3a")
    put_object(k4, b"a3b")
    sc, body = delete_objects_raw(obj_xml(k3) + "\n" + obj_xml(k4))
    record("A3", "Suspended: delete two different objects", sc, body)

    # A4: same key twice
    put_object(k5, b"a4")
    sc, body = delete_objects_raw(obj_xml(k5) + "\n" + obj_xml(k5))
    record("A4", "Suspended: same key twice in one request", sc, body)

    cleanup(k1, k2, k3, k4, k5)


# ============================================================================
# B. Versioning Enabled — no versionId
# ============================================================================

def test_b_enabled_no_vid():
    put_versioning("Enabled")

    k1 = f"delobj-b1-{uid()}"
    k2 = f"delobj-b2-{uid()}"
    k3 = f"delobj-b3-{uid()}"

    # B1: delete existing → DM created?
    v1 = put_object(k1, b"b1-data")
    sc, body = delete_objects_raw(obj_xml(k1))
    record("B1", "Enabled: delete existing (no versionId) → DM?", sc, body)

    # B2: delete nonexistent → DM?
    sc, body = delete_objects_raw(obj_xml(k2))
    record("B2", "Enabled: delete nonexistent (no versionId) → DM?", sc, body)

    # B3: same key twice without versionId → two DMs?
    put_object(k3, b"b3-data")
    sc, body = delete_objects_raw(obj_xml(k3) + "\n" + obj_xml(k3))
    record("B3", "Enabled: same key twice no versionId → two DMs?", sc, body)

    cleanup(k1, k2, k3)


# ============================================================================
# C. Versioning Enabled — with versionId
# ============================================================================

def test_c_enabled_with_vid():
    put_versioning("Enabled")

    k1 = f"delobj-c1-{uid()}"
    k2 = f"delobj-c2-{uid()}"
    k3 = f"delobj-c3-{uid()}"
    k4 = f"delobj-c4-{uid()}"

    # C1: delete specific version
    v1 = put_object(k1, b"c1-v1")
    v2 = put_object(k1, b"c1-v2")
    sc, body = delete_objects_raw(obj_xml(k1, v1))
    record("C1", f"Enabled: delete specific version {v1}", sc, body)

    # C2: delete nonexistent versionId (valid format but doesn't exist)
    fake_vid = v1  # already deleted above, or use a made-up one
    # Actually let's use a version from another object
    tmp_v = put_object(k2, b"tmp")
    sc, body = delete_objects_raw(obj_xml(k1, tmp_v))
    record("C2", "Enabled: delete non-existent versionId (valid format, wrong object)", sc, body)

    # C3: delete a delete marker by versionId
    del_resp = s3.delete_object(Bucket=BUCKET, Key=k3)
    # k3 doesn't exist, but in enabled mode this creates a DM
    put_object(k3, b"c3-data")
    del_resp = s3.delete_object(Bucket=BUCKET, Key=k3)
    dm_vid = del_resp.get("VersionId")
    sc, body = delete_objects_raw(obj_xml(k3, dm_vid))
    record("C3", f"Enabled: delete DM by versionId {dm_vid}", sc, body)

    # C4: delete the only/latest version by versionId
    v_only = put_object(k4, b"c4-only")
    sc, body = delete_objects_raw(obj_xml(k4, v_only))
    record("C4", f"Enabled: delete latest (only) version by versionId", sc, body)

    # verify object is gone
    try:
        r = s3.get_object(Bucket=BUCKET, Key=k4)
        record("C4-verify", "GET after deleting only version", 200, r["Body"].read().decode())
    except Exception as e:
        record("C4-verify", "GET after deleting only version", "error", str(e))

    cleanup(k1, k2, k3, k4)


# ============================================================================
# D. Versioning Enabled — mix with/without versionId in same request
# ============================================================================

def test_d_enabled_mix():
    put_versioning("Enabled")

    k1 = f"delobj-d1-{uid()}"
    k2 = f"delobj-d3-{uid()}"
    k3a = f"delobj-d4a-{uid()}"
    k3b = f"delobj-d4b-{uid()}"

    # D1: same key — first with versionId, second without
    v1 = put_object(k1, b"d1-v1")
    v2 = put_object(k1, b"d1-v2")
    sc, body = delete_objects_raw(obj_xml(k1, v1) + "\n" + obj_xml(k1))
    record("D1", "Enabled: same key — [with versionId] + [without versionId]", sc, body)

    cleanup(k1)

    # D2: same key — first without, second with versionId
    k1b = f"delobj-d2-{uid()}"
    v1 = put_object(k1b, b"d2-v1")
    v2 = put_object(k1b, b"d2-v2")
    sc, body = delete_objects_raw(obj_xml(k1b) + "\n" + obj_xml(k1b, v1))
    record("D2", "Enabled: same key — [without versionId] + [with versionId]", sc, body)

    cleanup(k1b)

    # D3: same key — delete latest version by versionId + without versionId
    v1 = put_object(k2, b"d3-v1")
    v2 = put_object(k2, b"d3-v2")
    sc, body = delete_objects_raw(obj_xml(k2, v2) + "\n" + obj_xml(k2))
    record("D3", "Enabled: same key — [delete LATEST by vid] + [without vid]", sc, body)

    cleanup(k2)

    # D4: two different keys — one with versionId, one without
    v3a = put_object(k3a, b"d4a")
    put_object(k3b, b"d4b")
    sc, body = delete_objects_raw(obj_xml(k3a, v3a) + "\n" + obj_xml(k3b))
    record("D4", "Enabled: different keys — one with vid, one without", sc, body)

    cleanup(k3a, k3b)


# ============================================================================
# E. Versioning Suspended
# ============================================================================

def test_e_suspended():
    put_versioning("Enabled")
    k1 = f"delobj-e1-{uid()}"
    k2 = f"delobj-e2-{uid()}"
    k3 = f"delobj-e3-{uid()}"
    k4 = f"delobj-e4-{uid()}"
    k5 = f"delobj-e5-{uid()}"

    # Create objects while Enabled, then Suspend
    v1 = put_object(k1, b"e1-data")
    v3 = put_object(k3, b"e3-data")
    v5 = put_object(k5, b"e5-data")

    put_versioning("Suspended")

    # E1: delete without versionId → null DM?
    sc, body = delete_objects_raw(obj_xml(k1))
    record("E1", "Suspended: delete existing (no versionId) → null DM?", sc, body)

    # E2: delete nonexistent
    sc, body = delete_objects_raw(obj_xml(k2))
    record("E2", "Suspended: delete nonexistent (no versionId)", sc, body)

    # E3: delete old version by versionId
    sc, body = delete_objects_raw(obj_xml(k3, v3))
    record("E3", f"Suspended: delete old version by versionId {v3}", sc, body)

    # E4: delete with versionId=null
    # First create a null version by putting while suspended
    put_object(k4, b"e4-null")
    sc, body = delete_objects_raw(obj_xml(k4, "null"))
    record("E4", "Suspended: delete with versionId=null", sc, body)

    # E5: same key — without versionId + with versionId of old version
    sc, body = delete_objects_raw(obj_xml(k5) + "\n" + obj_xml(k5, v5))
    record("E5", "Suspended: same key — [no vid] + [old vid]", sc, body)

    cleanup(k1, k2, k3, k4, k5)


# ============================================================================
# F. Quiet mode
# ============================================================================

def test_f_quiet():
    put_versioning("Enabled")

    k1 = f"delobj-f1-{uid()}"
    k2 = f"delobj-f2-{uid()}"

    # F1: quiet + successful delete
    put_object(k1, b"f1-data")
    sc, body = delete_objects_raw(obj_xml(k1), quiet=True)
    record("F1", "Enabled: Quiet=true, successful delete", sc, body)

    # F2: quiet + mix of existing and nonexistent
    put_object(k2, b"f2-data")
    sc, body = delete_objects_raw(
        obj_xml(k2) + "\n" + obj_xml(f"nonexistent-{uid()}"),
        quiet=True,
    )
    record("F2", "Enabled: Quiet=true, existing + nonexistent", sc, body)

    cleanup(k1, k2)


# ============================================================================
# Main
# ============================================================================

if __name__ == "__main__":
    print(f"Bucket: {BUCKET}")
    print(f"Region: {REGION}")
    print(f"Endpoint: {ENDPOINT}")
    print(f"Versioning: {get_versioning()}")

    test_a_disabled()
    test_b_enabled_no_vid()
    test_c_enabled_with_vid()
    test_d_enabled_mix()
    test_e_suspended()
    test_f_quiet()

    # Write results to md
    with open("deleteobjects_versioning.md", "r") as f:
        content = f.read()

    results_text = ""
    for test_id, desc, status, body in RESULTS:
        results_text += f"\n### {test_id}: {desc}\n"
        results_text += f"**Status:** {status}\n"
        results_text += f"```xml\n{body}\n```\n"

    content = content.replace(
        "_(заполняется после отправки запросов на AWS)_",
        results_text,
    )

    with open("deleteobjects_versioning.md", "w") as f:
        f.write(content)

    print(f"\n\n{'='*70}")
    print(f"Done! Results written to deleteobjects_versioning.md")
    print(f"Total tests: {len(RESULTS)}")
