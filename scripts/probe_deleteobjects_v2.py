#!/usr/bin/env python3
"""Probe DeleteObjects versioning — with ListObjectVersions verification.

For each test case:
1. Setup objects
2. Call DeleteObjects
3. Call ListObjectVersions to see what actually happened inside
"""

import hashlib
import base64
import uuid
import time
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import boto3
import requests
import urllib3
urllib3.disable_warnings()

from s3_compliance.signing import sign_request
from s3_compliance.utils import calculate_content_md5, calculate_content_sha256


def make_env(profile, region, endpoint=None, verify=True):
    session = boto3.Session(profile_name=profile, region_name=region)
    kwargs = dict(region_name=region, verify=verify)
    if endpoint:
        kwargs["endpoint_url"] = endpoint
        kwargs["config"] = boto3.session.Config(
            signature_version="s3v4", s3={"addressing_style": "path"}
        )
    s3 = session.client("s3", **kwargs)
    creds = session.get_credentials().get_frozen_credentials()
    return s3, creds, endpoint or f"https://s3.{region}.amazonaws.com"


# ---- Config ----
TARGET = os.getenv("TARGET", "aws")  # "aws" or "stage"

if TARGET == "stage":
    BUCKET = "s3-compliance-test"
    s3, creds, ENDPOINT = make_env("stage", "eu-west-1", "https://s3.stage.rabata.io", verify=False)
    REGION = "eu-west-1"
    VERIFY = False
    EXTRA_HEADERS = {"X-Forwarded-Proto": "https"}
else:
    BUCKET = "anon-reverse-s3-test-bucket"
    s3, creds, ENDPOINT = make_env("default", "us-east-1")
    REGION = "us-east-1"
    VERIFY = True
    EXTRA_HEADERS = {}

RESULTS = []


def uid():
    return uuid.uuid4().hex[:8]


def put_versioning(status):
    s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": status})
    time.sleep(0.5)


def put_object(key, body=b"data"):
    r = s3.put_object(Bucket=BUCKET, Key=key, Body=body)
    return r.get("VersionId")


def list_versions(key):
    """ListObjectVersions for a single key — return versions + delete markers."""
    r = s3.list_object_versions(Bucket=BUCKET, Prefix=key)
    versions = []
    for v in r.get("Versions", []):
        if v["Key"] == key:
            versions.append({
                "type": "version",
                "vid": v["VersionId"],
                "latest": v["IsLatest"],
                "size": v["Size"],
            })
    for dm in r.get("DeleteMarkers", []):
        if dm["Key"] == key:
            versions.append({
                "type": "DM",
                "vid": dm["VersionId"],
                "latest": dm["IsLatest"],
            })
    return versions


def delete_objects_raw(objects_xml, quiet=False):
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
        **EXTRA_HEADERS,
    }

    signed = sign_request(
        method="POST", url=url, headers=headers, body=body,
        credentials=creds, region=REGION,
    )

    resp = requests.post(url, data=body, headers=signed, verify=VERIFY)
    return resp.status_code, resp.text


def obj_xml(key, version_id=None):
    vid = f"\n        <VersionId>{version_id}</VersionId>" if version_id else ""
    return f"    <Object>\n        <Key>{key}</Key>{vid}\n    </Object>"


def fmt_versions(versions):
    if not versions:
        return "  (empty)"
    lines = []
    for v in versions:
        if v["type"] == "DM":
            lines.append(f"  DM  vid={v['vid']}  latest={v['latest']}")
        else:
            lines.append(f"  VER vid={v['vid']}  latest={v['latest']}  size={v['size']}")
    return "\n".join(lines)


def record(test_id, desc, status, body, before, after, keys):
    """Record test with before/after ListObjectVersions."""
    out = []
    out.append(f"## {test_id}: {desc}")
    out.append(f"**DeleteObjects status:** {status}")
    out.append(f"```xml\n{body}\n```")
    for key in keys:
        out.append(f"**ListObjectVersions `{key}` BEFORE:**")
        out.append(f"```\n{fmt_versions(before.get(key, []))}\n```")
        out.append(f"**ListObjectVersions `{key}` AFTER:**")
        out.append(f"```\n{fmt_versions(after.get(key, []))}\n```")
    text = "\n".join(out)
    RESULTS.append(text)
    print(f"\n{'='*70}")
    print(text)


def cleanup(*keys):
    for key in keys:
        try:
            r = s3.list_object_versions(Bucket=BUCKET, Prefix=key)
            for v in r.get("Versions", []):
                if v["Key"] == key:
                    s3.delete_object(Bucket=BUCKET, Key=key, VersionId=v["VersionId"])
            for dm in r.get("DeleteMarkers", []):
                if dm["Key"] == key:
                    s3.delete_object(Bucket=BUCKET, Key=key, VersionId=dm["VersionId"])
        except Exception:
            pass


# ============================================================================
# A. Suspended (as "disabled-like")
# ============================================================================

def test_a():
    put_versioning("Suspended")

    k1 = f"dov-a1-{uid()}"
    k2 = f"dov-a2-{uid()}"
    k3a = f"dov-a3a-{uid()}"
    k3b = f"dov-a3b-{uid()}"
    k4 = f"dov-a4-{uid()}"

    # A1
    put_object(k1, b"a1-data")
    before = {k1: list_versions(k1)}
    sc, body = delete_objects_raw(obj_xml(k1))
    after = {k1: list_versions(k1)}
    record("A1", "Suspended: delete existing (no vid)", sc, body, before, after, [k1])

    # A2
    before = {k2: list_versions(k2)}
    sc, body = delete_objects_raw(obj_xml(k2))
    after = {k2: list_versions(k2)}
    record("A2", "Suspended: delete nonexistent", sc, body, before, after, [k2])

    # A3
    put_object(k3a, b"a"); put_object(k3b, b"b")
    before = {k3a: list_versions(k3a), k3b: list_versions(k3b)}
    sc, body = delete_objects_raw(obj_xml(k3a) + "\n" + obj_xml(k3b))
    after = {k3a: list_versions(k3a), k3b: list_versions(k3b)}
    record("A3", "Suspended: delete two different objects", sc, body, before, after, [k3a, k3b])

    # A4
    put_object(k4, b"a4")
    before = {k4: list_versions(k4)}
    sc, body = delete_objects_raw(obj_xml(k4) + "\n" + obj_xml(k4))
    after = {k4: list_versions(k4)}
    record("A4", "Suspended: same key twice (no vid)", sc, body, before, after, [k4])

    cleanup(k1, k2, k3a, k3b, k4)


# ============================================================================
# B. Enabled — no versionId
# ============================================================================

def test_b():
    put_versioning("Enabled")

    k1 = f"dov-b1-{uid()}"
    k2 = f"dov-b2-{uid()}"
    k3 = f"dov-b3-{uid()}"

    # B1
    put_object(k1, b"b1")
    before = {k1: list_versions(k1)}
    sc, body = delete_objects_raw(obj_xml(k1))
    after = {k1: list_versions(k1)}
    record("B1", "Enabled: delete existing (no vid) → DM?", sc, body, before, after, [k1])

    # B2
    before = {k2: list_versions(k2)}
    sc, body = delete_objects_raw(obj_xml(k2))
    after = {k2: list_versions(k2)}
    record("B2", "Enabled: delete nonexistent (no vid) → DM?", sc, body, before, after, [k2])

    # B3
    put_object(k3, b"b3")
    before = {k3: list_versions(k3)}
    sc, body = delete_objects_raw(obj_xml(k3) + "\n" + obj_xml(k3))
    after = {k3: list_versions(k3)}
    record("B3", "Enabled: same key twice no vid → how many DMs?", sc, body, before, after, [k3])

    cleanup(k1, k2, k3)


# ============================================================================
# C. Enabled — with versionId
# ============================================================================

def test_c():
    put_versioning("Enabled")

    k1 = f"dov-c1-{uid()}"
    k2 = f"dov-c2-{uid()}"
    k3 = f"dov-c3-{uid()}"
    k4 = f"dov-c4-{uid()}"

    # C1: delete specific version (not latest)
    v1 = put_object(k1, b"c1-v1")
    v2 = put_object(k1, b"c1-v2")
    before = {k1: list_versions(k1)}
    sc, body = delete_objects_raw(obj_xml(k1, v1))
    after = {k1: list_versions(k1)}
    record("C1", f"Enabled: delete old version by vid", sc, body, before, after, [k1])

    # C2: non-existent versionId
    tmp_v = put_object(k2, b"tmp")
    before = {k1: list_versions(k1)}
    sc, body = delete_objects_raw(obj_xml(k1, tmp_v))
    after = {k1: list_versions(k1)}
    record("C2", "Enabled: delete non-existent versionId (from another object)", sc, body, before, after, [k1])

    # C3: delete a delete marker by versionId
    put_object(k3, b"c3")
    del_resp = s3.delete_object(Bucket=BUCKET, Key=k3)
    dm_vid = del_resp.get("VersionId")
    before = {k3: list_versions(k3)}
    sc, body = delete_objects_raw(obj_xml(k3, dm_vid))
    after = {k3: list_versions(k3)}
    record("C3", f"Enabled: delete DM by versionId → DeleteMarker in response?", sc, body, before, after, [k3])

    # C4: delete the only version
    v_only = put_object(k4, b"c4-only")
    before = {k4: list_versions(k4)}
    sc, body = delete_objects_raw(obj_xml(k4, v_only))
    after = {k4: list_versions(k4)}
    record("C4", "Enabled: delete only version by vid", sc, body, before, after, [k4])

    cleanup(k1, k2, k3, k4)


# ============================================================================
# D. Enabled — mix with/without versionId same key
# ============================================================================

def test_d():
    put_versioning("Enabled")

    # D1: [with vid] + [without vid]
    k1 = f"dov-d1-{uid()}"
    v1 = put_object(k1, b"d1-v1")
    v2 = put_object(k1, b"d1-v2")
    before = {k1: list_versions(k1)}
    sc, body = delete_objects_raw(obj_xml(k1, v1) + "\n" + obj_xml(k1))
    after = {k1: list_versions(k1)}
    record("D1", "Enabled: same key [vid=old] + [no vid]", sc, body, before, after, [k1])
    cleanup(k1)

    # D2: [without vid] + [with vid]
    k2 = f"dov-d2-{uid()}"
    v1 = put_object(k2, b"d2-v1")
    v2 = put_object(k2, b"d2-v2")
    before = {k2: list_versions(k2)}
    sc, body = delete_objects_raw(obj_xml(k2) + "\n" + obj_xml(k2, v1))
    after = {k2: list_versions(k2)}
    record("D2", "Enabled: same key [no vid] + [vid=old]", sc, body, before, after, [k2])
    cleanup(k2)

    # D3: [delete LATEST by vid] + [without vid]
    k3 = f"dov-d3-{uid()}"
    v1 = put_object(k3, b"d3-v1")
    v2 = put_object(k3, b"d3-v2")
    before = {k3: list_versions(k3)}
    sc, body = delete_objects_raw(obj_xml(k3, v2) + "\n" + obj_xml(k3))
    after = {k3: list_versions(k3)}
    record("D3", "Enabled: same key [vid=LATEST] + [no vid]", sc, body, before, after, [k3])
    cleanup(k3)

    # D4: two different keys
    k4a = f"dov-d4a-{uid()}"
    k4b = f"dov-d4b-{uid()}"
    va = put_object(k4a, b"d4a")
    put_object(k4b, b"d4b")
    before = {k4a: list_versions(k4a), k4b: list_versions(k4b)}
    sc, body = delete_objects_raw(obj_xml(k4a, va) + "\n" + obj_xml(k4b))
    after = {k4a: list_versions(k4a), k4b: list_versions(k4b)}
    record("D4", "Enabled: different keys [vid] + [no vid]", sc, body, before, after, [k4a, k4b])
    cleanup(k4a, k4b)


# ============================================================================
# E. Suspended
# ============================================================================

def test_e():
    put_versioning("Enabled")
    k1 = f"dov-e1-{uid()}"
    k2 = f"dov-e2-{uid()}"
    k3 = f"dov-e3-{uid()}"
    k4 = f"dov-e4-{uid()}"
    k5 = f"dov-e5-{uid()}"

    v1 = put_object(k1, b"e1")
    v3 = put_object(k3, b"e3")
    v5 = put_object(k5, b"e5")

    put_versioning("Suspended")

    # E1: no vid
    before = {k1: list_versions(k1)}
    sc, body = delete_objects_raw(obj_xml(k1))
    after = {k1: list_versions(k1)}
    record("E1", "Suspended: delete existing (no vid)", sc, body, before, after, [k1])

    # E2: nonexistent
    before = {k2: list_versions(k2)}
    sc, body = delete_objects_raw(obj_xml(k2))
    after = {k2: list_versions(k2)}
    record("E2", "Suspended: delete nonexistent (no vid)", sc, body, before, after, [k2])

    # E3: old version by vid
    before = {k3: list_versions(k3)}
    sc, body = delete_objects_raw(obj_xml(k3, v3))
    after = {k3: list_versions(k3)}
    record("E3", "Suspended: delete old version by vid", sc, body, before, after, [k3])

    # E4: versionId=null
    put_object(k4, b"e4-null")  # creates null version in suspended
    before = {k4: list_versions(k4)}
    sc, body = delete_objects_raw(obj_xml(k4, "null"))
    after = {k4: list_versions(k4)}
    record("E4", "Suspended: delete with versionId=null", sc, body, before, after, [k4])

    # E5: [no vid] + [old vid]
    before = {k5: list_versions(k5)}
    sc, body = delete_objects_raw(obj_xml(k5) + "\n" + obj_xml(k5, v5))
    after = {k5: list_versions(k5)}
    record("E5", "Suspended: same key [no vid] + [old vid]", sc, body, before, after, [k5])

    cleanup(k1, k2, k3, k4, k5)


# ============================================================================
# F. Quiet
# ============================================================================

def test_f():
    put_versioning("Enabled")

    k1 = f"dov-f1-{uid()}"
    k2 = f"dov-f2-{uid()}"

    put_object(k1, b"f1")
    before = {k1: list_versions(k1)}
    sc, body = delete_objects_raw(obj_xml(k1), quiet=True)
    after = {k1: list_versions(k1)}
    record("F1", "Enabled: Quiet=true", sc, body, before, after, [k1])

    put_object(k2, b"f2")
    nx = f"nonexistent-{uid()}"
    before = {k2: list_versions(k2), nx: list_versions(nx)}
    sc, body = delete_objects_raw(obj_xml(k2) + "\n" + obj_xml(nx), quiet=True)
    after = {k2: list_versions(k2), nx: list_versions(nx)}
    record("F2", "Enabled: Quiet=true, existing + nonexistent", sc, body, before, after, [k2, nx])

    cleanup(k1, k2)


# ============================================================================

if __name__ == "__main__":
    out_file = f"deleteobjects_versioning_{TARGET}_v2.md"
    print(f"Target: {TARGET}")
    print(f"Bucket: {BUCKET}")
    print(f"Endpoint: {ENDPOINT}")
    print(f"Output: {out_file}")

    test_a()
    test_b()
    test_c()
    test_d()
    test_e()
    test_f()

    with open(out_file, "w") as f:
        f.write(f"# DeleteObjects Versioning — {TARGET.upper()} (with ListObjectVersions)\n\n")
        for r in RESULTS:
            f.write(r + "\n\n---\n\n")

    print(f"\n\nDone! {len(RESULTS)} tests → {out_file}")
