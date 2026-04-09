#!/usr/bin/env python3
"""Probe CopyObject, UploadPartCopy, GetObjectACL, PutObjectACL with DeleteMarker sources on real AWS S3.

Sends requests and records raw responses for reverse engineering.

Part 1 — DeleteMarker tests:
  A. CopyObject — source is DeleteMarker
  B. UploadPartCopy — source is DeleteMarker
  C. GetObjectACL — target is DeleteMarker
  D. PutObjectACL — target is DeleteMarker

Part 2 — Control (real objects, no delete markers):
  E. CopyObject — real object
  F. UploadPartCopy — real object
  G. GetObjectACL — real object
  H. PutObjectACL — real object
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
    BUCKET = os.getenv("TEST_BUCKET_NAME", "s3-compliance-test")
    s3, creds, ENDPOINT = make_env("stage", "eu-west-1", os.getenv("S3_ENDPOINT", "https://s3.stage.rabata.io"), verify=False)
    REGION = "eu-west-1"
    VERIFY = False
    EXTRA_HEADERS = {"X-Forwarded-Proto": "https"}
else:
    BUCKET = os.getenv("TEST_BUCKET_NAME", "anon-reverse-s3-test-bucket")
    s3, creds, ENDPOINT = make_env("default", "us-east-1")
    REGION = "us-east-1"
    VERIFY = True
    EXTRA_HEADERS = {}

RESULTS = []


def uid():
    return uuid.uuid4().hex[:8]


def do_request(method, path, body=b"", headers=None, qp=""):
    hdrs = dict(headers) if headers else {}
    hdrs.update(EXTRA_HEADERS)
    url = f"{ENDPOINT}{path}"
    if qp:
        url += qp
    if "x-amz-content-sha256" not in hdrs:
        hdrs["x-amz-content-sha256"] = calculate_content_sha256(body if body else b"")
    signed = sign_request(
        method=method, url=url, headers=hdrs,
        body=body if body else b"", credentials=creds, region=REGION,
    )
    func = getattr(requests, method.lower())
    resp = func(url, data=body, headers=signed, verify=VERIFY)
    return resp


def put_versioning(status):
    body = f'''<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Status>{status}</Status>
</VersioningConfiguration>'''.encode("utf-8")
    resp = do_request("PUT", f"/{BUCKET}", body=body,
                      headers={"Content-Type": "application/xml"}, qp="?versioning")
    assert resp.status_code == 200, f"PutVersioning({status}) failed: {resp.status_code} {resp.text}"
    time.sleep(0.5)


def put_object(key, body=b"data"):
    r = s3.put_object(Bucket=BUCKET, Key=key, Body=body)
    return r.get("VersionId")


def delete_object(key):
    """Delete object (creates DM when versioning enabled). Returns (versionId, isDeleteMarker)."""
    r = s3.delete_object(Bucket=BUCKET, Key=key)
    return r.get("VersionId"), r.get("DeleteMarker", False)


def list_versions(key):
    r = s3.list_object_versions(Bucket=BUCKET, Prefix=key)
    versions = [v for v in r.get("Versions", []) if v["Key"] == key]
    markers = [m for m in r.get("DeleteMarkers", []) if m["Key"] == key]
    return versions, markers


def make_acl_xml():
    """Build a valid private ACL XML for PutObjectACL using dynamic owner ID."""
    oid = OWNER_ID or "10adec58aa82e4276fcd6bffd437ba0e42ae890098cf4bba7aa0aa8215241bfd"
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Owner>
        <ID>{oid}</ID>
    </Owner>
    <AccessControlList>
        <Grant>
            <Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser">
                <ID>{oid}</ID>
            </Grantee>
            <Permission>FULL_CONTROL</Permission>
        </Grant>
    </AccessControlList>
</AccessControlPolicy>'''.encode("utf-8")


def format_response(resp):
    """Format response for recording."""
    lines = []
    lines.append(f"HTTP {resp.status_code}")
    for k, v in sorted(resp.headers.items()):
        kl = k.lower()
        if kl in ("x-amz-request-id", "x-amz-id-2", "date", "server",
                   "x-amz-trace-id", "connection", "transfer-encoding",
                   "content-length", "keep-alive"):
            continue
        lines.append(f"  {k}: {v}")
    lines.append("")
    if resp.text:
        lines.append(resp.text)
    return "\n".join(lines)


def record(test_id, description, resp, extra_info=""):
    """Record test result."""
    formatted = format_response(resp)
    RESULTS.append((test_id, description, resp.status_code, formatted, extra_info))
    print(f"\n{'='*70}")
    print(f"## {test_id}: {description}")
    if extra_info:
        print(f"  [{extra_info}]")
    print(f"Status: {resp.status_code}")
    print(formatted)


def cleanup(*keys):
    """Best-effort cleanup of all versions of given keys."""
    for key in keys:
        try:
            versions, markers = list_versions(key)
            for v in versions:
                s3.delete_object(Bucket=BUCKET, Key=key, VersionId=v["VersionId"])
            for m in markers:
                s3.delete_object(Bucket=BUCKET, Key=key, VersionId=m["VersionId"])
        except Exception:
            pass


def abort_mpu_safe(key, upload_id, bucket=None):
    try:
        s3.abort_multipart_upload(Bucket=bucket or BUCKET, Key=key, UploadId=upload_id)
    except Exception:
        pass


# ---- ACL bucket helpers ----

ACL_BUCKET = None
OWNER_ID = None


def create_acl_bucket():
    """Create a temporary bucket with ACLs enabled + versioning."""
    global ACL_BUCKET, OWNER_ID
    ACL_BUCKET = f"vmix-acl-{uid()}-{uid()}"
    print(f"\nCreating ACL bucket: {ACL_BUCKET}")
    s3.create_bucket(
        Bucket=ACL_BUCKET,
        ObjectOwnership="BucketOwnerPreferred",
    )
    # Disable Block Public Access for ACLs to work
    s3.delete_public_access_block(Bucket=ACL_BUCKET)
    # Enable versioning
    s3.put_bucket_versioning(
        Bucket=ACL_BUCKET,
        VersioningConfiguration={"Status": "Enabled"},
    )
    time.sleep(1)
    # Get owner ID
    resp = s3.get_bucket_acl(Bucket=ACL_BUCKET)
    OWNER_ID = resp["Owner"]["ID"]
    print(f"  Owner ID: {OWNER_ID}")
    print(f"  Versioning: Enabled, ACLs: BucketOwnerPreferred")


def delete_acl_bucket():
    """Delete the temporary ACL bucket and all its contents."""
    if not ACL_BUCKET:
        return
    print(f"\nCleaning up ACL bucket: {ACL_BUCKET}")
    try:
        # Delete all versions and delete markers
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=ACL_BUCKET):
            for v in page.get("Versions", []):
                s3.delete_object(Bucket=ACL_BUCKET, Key=v["Key"], VersionId=v["VersionId"])
            for dm in page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=ACL_BUCKET, Key=dm["Key"], VersionId=dm["VersionId"])
        s3.delete_bucket(Bucket=ACL_BUCKET)
        print(f"  Deleted.")
    except Exception as e:
        print(f"  Cleanup error: {e}")


def put_object_acl_bucket(key, body=b"data"):
    r = s3.put_object(Bucket=ACL_BUCKET, Key=key, Body=body)
    return r.get("VersionId")


def delete_object_acl_bucket(key):
    r = s3.delete_object(Bucket=ACL_BUCKET, Key=key)
    return r.get("VersionId"), r.get("DeleteMarker", False)


def cleanup_acl(*keys):
    for key in keys:
        try:
            r = s3.list_object_versions(Bucket=ACL_BUCKET, Prefix=key)
            for v in r.get("Versions", []):
                if v["Key"] == key:
                    s3.delete_object(Bucket=ACL_BUCKET, Key=key, VersionId=v["VersionId"])
            for m in r.get("DeleteMarkers", []):
                if m["Key"] == key:
                    s3.delete_object(Bucket=ACL_BUCKET, Key=key, VersionId=m["VersionId"])
        except Exception:
            pass


# ############################################################################
#
#   PART 1: DELETE MARKER TESTS
#
# ############################################################################


# ============================================================================
# A. CopyObject — source is a DeleteMarker
# ============================================================================

def test_a_copyobject_deletemarker():
    src = f"vmix-a-src-{uid()}"
    dst = f"vmix-a-dst-{uid()}"

    # --- A1: source is ONLY a DM (no real versions), no versionId ---
    dm_vid, _ = delete_object(src)
    resp = do_request(
        "PUT", f"/{BUCKET}/{dst}-a1",
        headers={"x-amz-copy-source": f"/{BUCKET}/{src}"},
    )
    record("A1", "CopyObject: source ONLY DM, no versionId", resp,
           f"DM={dm_vid}")

    # --- A2: source is ONLY a DM, with versionId=DM ---
    resp = do_request(
        "PUT", f"/{BUCKET}/{dst}-a2",
        headers={"x-amz-copy-source": f"/{BUCKET}/{src}?versionId={dm_vid}"},
    )
    record("A2", "CopyObject: source ONLY DM, versionId=DM", resp,
           f"DM={dm_vid}")

    cleanup(src, f"{dst}-a1", f"{dst}-a2")

    # --- A3: source has real versions + DM on top, no versionId ---
    src2 = f"vmix-a-src2-{uid()}"
    v1 = put_object(src2, b"version-1")
    v2 = put_object(src2, b"version-2")
    dm2_vid, _ = delete_object(src2)

    resp = do_request(
        "PUT", f"/{BUCKET}/{dst}-a3",
        headers={"x-amz-copy-source": f"/{BUCKET}/{src2}"},
    )
    record("A3", "CopyObject: source has versions+DM, no versionId (latest=DM)", resp,
           f"v1={v1}, v2={v2}, DM={dm2_vid}")

    # --- A4: source has real versions + DM, versionId=DM ---
    resp = do_request(
        "PUT", f"/{BUCKET}/{dst}-a4",
        headers={"x-amz-copy-source": f"/{BUCKET}/{src2}?versionId={dm2_vid}"},
    )
    record("A4", "CopyObject: source has versions+DM, versionId=DM", resp,
           f"DM={dm2_vid}")

    cleanup(src2, f"{dst}-a3", f"{dst}-a4")


# ============================================================================
# B. UploadPartCopy — source is a DeleteMarker
# ============================================================================

def test_b_uploadpartcopy_deletemarker():
    src = f"vmix-b-src-{uid()}"
    dst = f"vmix-b-dst-{uid()}"
    upload_id = None

    try:
        v1 = put_object(src, b"x" * 1024)
        dm_vid, _ = delete_object(src)

        mpu = s3.create_multipart_upload(Bucket=BUCKET, Key=dst)
        upload_id = mpu["UploadId"]

        # --- B1: no versionId, latest=DM ---
        resp = do_request(
            "PUT", f"/{BUCKET}/{dst}",
            headers={"x-amz-copy-source": f"/{BUCKET}/{src}"},
            qp=f"?uploadId={upload_id}&partNumber=1",
        )
        record("B1", "UploadPartCopy: source has versions+DM, no versionId (latest=DM)", resp,
               f"v1={v1}, DM={dm_vid}")

        # --- B2: versionId=DM ---
        resp = do_request(
            "PUT", f"/{BUCKET}/{dst}",
            headers={"x-amz-copy-source": f"/{BUCKET}/{src}?versionId={dm_vid}"},
            qp=f"?uploadId={upload_id}&partNumber=2",
        )
        record("B2", "UploadPartCopy: source has versions+DM, versionId=DM", resp,
               f"DM={dm_vid}")

        # --- B3: source is ONLY a DM, no versionId ---
        src2 = f"vmix-b-src2-{uid()}"
        dm2_vid, _ = delete_object(src2)
        resp = do_request(
            "PUT", f"/{BUCKET}/{dst}",
            headers={"x-amz-copy-source": f"/{BUCKET}/{src2}"},
            qp=f"?uploadId={upload_id}&partNumber=3",
        )
        record("B3", "UploadPartCopy: source ONLY DM, no versionId", resp,
               f"DM={dm2_vid}")

        cleanup(src2)

    finally:
        if upload_id:
            abort_mpu_safe(dst, upload_id)
        cleanup(src, dst)


# ============================================================================
# B2. UploadPart — destination key is a DeleteMarker
# ============================================================================

def test_b2_uploadpart_deletemarker():
    key = f"vmix-b2-{uid()}"
    upload_id = None

    try:
        # --- B2a: CreateMultipartUpload + UploadPart on key that has versions+DM ---
        v1 = put_object(key, b"original-data")
        dm_vid, _ = delete_object(key)

        mpu = s3.create_multipart_upload(Bucket=BUCKET, Key=key)
        upload_id = mpu["UploadId"]

        resp = do_request(
            "PUT", f"/{BUCKET}/{key}",
            body=b"x" * 1024,
            qp=f"?uploadId={upload_id}&partNumber=1",
        )
        record("B2a", "UploadPart: dest key has versions+DM", resp,
               f"v1={v1}, DM={dm_vid}, uploadId={upload_id}")

    finally:
        if upload_id:
            abort_mpu_safe(key, upload_id)
        cleanup(key)

    # --- B2b: CreateMultipartUpload + UploadPart on key that is ONLY DM ---
    key2 = f"vmix-b2b-{uid()}"
    upload_id = None
    try:
        dm2_vid, _ = delete_object(key2)

        mpu = s3.create_multipart_upload(Bucket=BUCKET, Key=key2)
        upload_id = mpu["UploadId"]

        resp = do_request(
            "PUT", f"/{BUCKET}/{key2}",
            body=b"y" * 1024,
            qp=f"?uploadId={upload_id}&partNumber=1",
        )
        record("B2b", "UploadPart: dest key is ONLY DM", resp,
               f"DM={dm2_vid}, uploadId={upload_id}")

    finally:
        if upload_id:
            abort_mpu_safe(key2, upload_id)
        cleanup(key2)


# ============================================================================
# C. GetObjectACL — target is a DeleteMarker
# ============================================================================

def test_c_getobjectacl_deletemarker():
    key = f"vmix-c-{uid()}"

    # --- C1: has versions + DM on top, no versionId ---
    v1 = put_object(key, b"acl-data")
    dm_vid, _ = delete_object(key)

    resp = do_request("GET", f"/{BUCKET}/{key}", qp="?acl")
    record("C1", "GetObjectACL: has versions+DM, no versionId (latest=DM)", resp,
           f"v1={v1}, DM={dm_vid}")

    # --- C2: ONLY DM, no versionId ---
    key2 = f"vmix-c2-{uid()}"
    dm2_vid, _ = delete_object(key2)

    resp = do_request("GET", f"/{BUCKET}/{key2}", qp="?acl")
    record("C2", "GetObjectACL: ONLY DM, no versionId", resp,
           f"DM={dm2_vid}")

    # --- C3: has versions + DM, versionId=DM ---
    resp = do_request("GET", f"/{BUCKET}/{key}", qp=f"?acl&versionId={dm_vid}")
    record("C3", "GetObjectACL: has versions+DM, versionId=DM", resp,
           f"v1={v1}, DM={dm_vid}")

    # --- C4: ONLY DM, versionId=DM ---
    resp = do_request("GET", f"/{BUCKET}/{key2}", qp=f"?acl&versionId={dm2_vid}")
    record("C4", "GetObjectACL: ONLY DM, versionId=DM", resp,
           f"DM={dm2_vid}")

    cleanup(key, key2)


# ============================================================================
# D. PutObjectACL — target is a DeleteMarker (ACL-enabled bucket)
# ============================================================================

def test_d_putobjectacl_deletemarker():
    key = f"vmix-d-{uid()}"
    acl_body = make_acl_xml()

    # --- D1: has versions + DM on top, no versionId ---
    v1 = put_object_acl_bucket(key, b"acl-put-data")
    dm_vid, _ = delete_object_acl_bucket(key)

    resp = do_request("PUT", f"/{ACL_BUCKET}/{key}", body=acl_body,
                      headers={"Content-Type": "application/xml"},
                      qp="?acl")
    record("D1", "PutObjectACL: has versions+DM, no versionId (latest=DM)", resp,
           f"bucket={ACL_BUCKET}, v1={v1}, DM={dm_vid}")

    # --- D2: ONLY DM, no versionId ---
    key2 = f"vmix-d2-{uid()}"
    dm2_vid, _ = delete_object_acl_bucket(key2)

    resp = do_request("PUT", f"/{ACL_BUCKET}/{key2}", body=acl_body,
                      headers={"Content-Type": "application/xml"},
                      qp="?acl")
    record("D2", "PutObjectACL: ONLY DM, no versionId", resp,
           f"bucket={ACL_BUCKET}, DM={dm2_vid}")

    # --- D3: has versions + DM, versionId=DM ---
    resp = do_request("PUT", f"/{ACL_BUCKET}/{key}", body=acl_body,
                      headers={"Content-Type": "application/xml"},
                      qp=f"?acl&versionId={dm_vid}")
    record("D3", "PutObjectACL: has versions+DM, versionId=DM", resp,
           f"bucket={ACL_BUCKET}, v1={v1}, DM={dm_vid}")

    # --- D4: ONLY DM, versionId=DM ---
    resp = do_request("PUT", f"/{ACL_BUCKET}/{key2}", body=acl_body,
                      headers={"Content-Type": "application/xml"},
                      qp=f"?acl&versionId={dm2_vid}")
    record("D4", "PutObjectACL: ONLY DM, versionId=DM", resp,
           f"bucket={ACL_BUCKET}, DM={dm2_vid}")

    cleanup_acl(key, key2)


# ############################################################################
#
#   PART 2: CONTROL — REAL OBJECTS (no delete markers)
#
# ############################################################################


# ============================================================================
# E. CopyObject — real object (control)
# ============================================================================

def test_e_copyobject_real():
    src = f"vmix-e-src-{uid()}"
    dst = f"vmix-e-dst-{uid()}"

    v1 = put_object(src, b"real-copy-source")

    # --- E1: no versionId ---
    resp = do_request(
        "PUT", f"/{BUCKET}/{dst}-e1",
        headers={"x-amz-copy-source": f"/{BUCKET}/{src}"},
    )
    record("E1", "CopyObject: real object, no versionId (control)", resp,
           f"v1={v1}")

    # --- E2: with versionId ---
    resp = do_request(
        "PUT", f"/{BUCKET}/{dst}-e2",
        headers={"x-amz-copy-source": f"/{BUCKET}/{src}?versionId={v1}"},
    )
    record("E2", "CopyObject: real object, versionId=real (control)", resp,
           f"v1={v1}")

    cleanup(src, f"{dst}-e1", f"{dst}-e2")


# ============================================================================
# F. UploadPartCopy — real object (control)
# ============================================================================

def test_f_uploadpartcopy_real():
    src = f"vmix-f-src-{uid()}"
    dst = f"vmix-f-dst-{uid()}"
    upload_id = None

    try:
        v1 = put_object(src, b"x" * 1024)

        mpu = s3.create_multipart_upload(Bucket=BUCKET, Key=dst)
        upload_id = mpu["UploadId"]

        # --- F1: no versionId ---
        resp = do_request(
            "PUT", f"/{BUCKET}/{dst}",
            headers={"x-amz-copy-source": f"/{BUCKET}/{src}"},
            qp=f"?uploadId={upload_id}&partNumber=1",
        )
        record("F1", "UploadPartCopy: real object, no versionId (control)", resp,
               f"v1={v1}")

        # --- F2: with versionId ---
        resp = do_request(
            "PUT", f"/{BUCKET}/{dst}",
            headers={"x-amz-copy-source": f"/{BUCKET}/{src}?versionId={v1}"},
            qp=f"?uploadId={upload_id}&partNumber=2",
        )
        record("F2", "UploadPartCopy: real object, versionId=real (control)", resp,
               f"v1={v1}")

    finally:
        if upload_id:
            abort_mpu_safe(dst, upload_id)
        cleanup(src, dst)


# ============================================================================
# F2. UploadPart — real object (control)
# ============================================================================

def test_f2_uploadpart_real():
    key = f"vmix-f2-{uid()}"
    upload_id = None

    try:
        v1 = put_object(key, b"existing-data")

        mpu = s3.create_multipart_upload(Bucket=BUCKET, Key=key)
        upload_id = mpu["UploadId"]

        # --- F2a: UploadPart on existing key ---
        resp = do_request(
            "PUT", f"/{BUCKET}/{key}",
            body=b"z" * 1024,
            qp=f"?uploadId={upload_id}&partNumber=1",
        )
        record("F2a", "UploadPart: real object, existing key (control)", resp,
               f"v1={v1}, uploadId={upload_id}")

    finally:
        if upload_id:
            abort_mpu_safe(key, upload_id)
        cleanup(key)

    # --- F2b: UploadPart on new key (no prior versions) ---
    key2 = f"vmix-f2b-{uid()}"
    upload_id = None
    try:
        mpu = s3.create_multipart_upload(Bucket=BUCKET, Key=key2)
        upload_id = mpu["UploadId"]

        resp = do_request(
            "PUT", f"/{BUCKET}/{key2}",
            body=b"w" * 1024,
            qp=f"?uploadId={upload_id}&partNumber=1",
        )
        record("F2b", "UploadPart: new key, no prior versions (control)", resp,
               f"uploadId={upload_id}")

    finally:
        if upload_id:
            abort_mpu_safe(key2, upload_id)
        cleanup(key2)


# ============================================================================
# G. GetObjectACL — real object (control)
# ============================================================================

def test_g_getobjectacl_real():
    key = f"vmix-g-{uid()}"
    v1 = put_object(key, b"acl-real-data")

    # --- G1: no versionId ---
    resp = do_request("GET", f"/{BUCKET}/{key}", qp="?acl")
    record("G1", "GetObjectACL: real object, no versionId (control)", resp,
           f"v1={v1}")

    # --- G2: with versionId ---
    resp = do_request("GET", f"/{BUCKET}/{key}", qp=f"?acl&versionId={v1}")
    record("G2", "GetObjectACL: real object, versionId=real (control)", resp,
           f"v1={v1}")

    cleanup(key)


# ============================================================================
# H. PutObjectACL — real object (control, ACL-enabled bucket)
# ============================================================================

def test_h_putobjectacl_real():
    key = f"vmix-h-{uid()}"
    v1 = put_object_acl_bucket(key, b"acl-put-real-data")
    acl_body = make_acl_xml()

    # --- H1: no versionId ---
    resp = do_request("PUT", f"/{ACL_BUCKET}/{key}", body=acl_body,
                      headers={"Content-Type": "application/xml"},
                      qp="?acl")
    record("H1", "PutObjectACL: real object, no versionId (control)", resp,
           f"bucket={ACL_BUCKET}, v1={v1}")

    # --- H2: with versionId ---
    resp = do_request("PUT", f"/{ACL_BUCKET}/{key}", body=acl_body,
                      headers={"Content-Type": "application/xml"},
                      qp=f"?acl&versionId={v1}")
    record("H2", "PutObjectACL: real object, versionId=real (control)", resp,
           f"bucket={ACL_BUCKET}, v1={v1}")

    cleanup_acl(key)


# ############################################################################
#
#   PART 3: INVALID VERSION IDs (empty string, "abc")
#
# ############################################################################


# ============================================================================
# I. CopyObject — invalid versionId in x-amz-copy-source
# ============================================================================

def test_i_copyobject_invalid_versionid():
    src = f"vmix-i-src-{uid()}"
    dst = f"vmix-i-dst-{uid()}"
    v1 = put_object(src, b"copy-src-data")

    # --- I1: versionId= (empty) ---
    resp = do_request(
        "PUT", f"/{BUCKET}/{dst}-i1",
        headers={"x-amz-copy-source": f"/{BUCKET}/{src}?versionId="},
    )
    record("I1", "CopyObject: versionId= (empty)", resp, f"v1={v1}")

    # --- I2: versionId=abc ---
    resp = do_request(
        "PUT", f"/{BUCKET}/{dst}-i2",
        headers={"x-amz-copy-source": f"/{BUCKET}/{src}?versionId=abc"},
    )
    record("I2", "CopyObject: versionId=abc", resp, f"v1={v1}")

    cleanup(src, f"{dst}-i1", f"{dst}-i2")


# ============================================================================
# J. UploadPartCopy — invalid versionId in x-amz-copy-source
# ============================================================================

def test_j_uploadpartcopy_invalid_versionid():
    src = f"vmix-j-src-{uid()}"
    dst = f"vmix-j-dst-{uid()}"
    upload_id = None

    try:
        v1 = put_object(src, b"x" * 1024)

        mpu = s3.create_multipart_upload(Bucket=BUCKET, Key=dst)
        upload_id = mpu["UploadId"]

        # --- J1: versionId= (empty) ---
        resp = do_request(
            "PUT", f"/{BUCKET}/{dst}",
            headers={"x-amz-copy-source": f"/{BUCKET}/{src}?versionId="},
            qp=f"?uploadId={upload_id}&partNumber=1",
        )
        record("J1", "UploadPartCopy: versionId= (empty)", resp, f"v1={v1}")

        # --- J2: versionId=abc ---
        resp = do_request(
            "PUT", f"/{BUCKET}/{dst}",
            headers={"x-amz-copy-source": f"/{BUCKET}/{src}?versionId=abc"},
            qp=f"?uploadId={upload_id}&partNumber=2",
        )
        record("J2", "UploadPartCopy: versionId=abc", resp, f"v1={v1}")

    finally:
        if upload_id:
            abort_mpu_safe(dst, upload_id)
        cleanup(src, dst)


# ============================================================================
# J2. UploadPart — invalid versionId in query param
# ============================================================================

def test_j2_uploadpart_invalid_versionid():
    key = f"vmix-j2-{uid()}"
    upload_id = None

    try:
        v1 = put_object(key, b"x" * 1024)

        mpu = s3.create_multipart_upload(Bucket=BUCKET, Key=key)
        upload_id = mpu["UploadId"]

        # --- J2a: versionId= (empty) ---
        resp = do_request(
            "PUT", f"/{BUCKET}/{key}",
            body=b"part-data",
            qp=f"?uploadId={upload_id}&partNumber=1&versionId=",
        )
        record("J2a", "UploadPart: versionId= (empty)", resp, f"v1={v1}")

        # --- J2b: versionId=abc ---
        resp = do_request(
            "PUT", f"/{BUCKET}/{key}",
            body=b"part-data",
            qp=f"?uploadId={upload_id}&partNumber=2&versionId=abc",
        )
        record("J2b", "UploadPart: versionId=abc", resp, f"v1={v1}")

        # --- J2c: versionId=real version ---
        resp = do_request(
            "PUT", f"/{BUCKET}/{key}",
            body=b"part-data",
            qp=f"?uploadId={upload_id}&partNumber=3&versionId={v1}",
        )
        record("J2c", "UploadPart: versionId=real version", resp, f"v1={v1}")

    finally:
        if upload_id:
            abort_mpu_safe(key, upload_id)
        cleanup(key)


# ============================================================================
# K. GetObjectACL — invalid versionId in query param
# ============================================================================

def test_k_getobjectacl_invalid_versionid():
    key = f"vmix-k-{uid()}"
    v1 = put_object(key, b"acl-data-k")

    # --- K1: versionId= (empty) ---
    resp = do_request("GET", f"/{BUCKET}/{key}", qp="?acl&versionId=")
    record("K1", "GetObjectACL: versionId= (empty)", resp, f"v1={v1}")

    # --- K2: versionId=abc ---
    resp = do_request("GET", f"/{BUCKET}/{key}", qp="?acl&versionId=abc")
    record("K2", "GetObjectACL: versionId=abc", resp, f"v1={v1}")

    cleanup(key)


# ============================================================================
# L. PutObjectACL — invalid versionId in query param (ACL-enabled bucket)
# ============================================================================

def test_l_putobjectacl_invalid_versionid():
    key = f"vmix-l-{uid()}"
    v1 = put_object_acl_bucket(key, b"acl-data-l")
    acl_body = make_acl_xml()

    # --- L1: versionId= (empty) ---
    resp = do_request("PUT", f"/{ACL_BUCKET}/{key}", body=acl_body,
                      headers={"Content-Type": "application/xml"},
                      qp="?acl&versionId=")
    record("L1", "PutObjectACL: versionId= (empty)", resp,
           f"bucket={ACL_BUCKET}, v1={v1}")

    # --- L2: versionId=abc ---
    resp = do_request("PUT", f"/{ACL_BUCKET}/{key}", body=acl_body,
                      headers={"Content-Type": "application/xml"},
                      qp="?acl&versionId=abc")
    record("L2", "PutObjectACL: versionId=abc", resp,
           f"bucket={ACL_BUCKET}, v1={v1}")

    cleanup_acl(key)


# ============================================================================
# Main
# ============================================================================

def run_test(fn):
    """Run a test function, catching and recording errors."""
    try:
        fn()
    except Exception as e:
        print(f"\n  !!! {fn.__name__} CRASHED: {e}")
        RESULTS.append((fn.__name__, f"CRASHED: {e}", "ERROR", str(e), ""))


if __name__ == "__main__":
    print(f"Target: {TARGET}")
    print(f"Bucket: {BUCKET}")
    print(f"Region: {REGION}")
    print(f"Endpoint: {ENDPOINT}")

    put_versioning("Enabled")
    print("Versioning: Enabled")
    print("=" * 70)

    # Part 1: DeleteMarker tests
    print("\n>>> PART 1: DELETE MARKER TESTS <<<")
    run_test(test_a_copyobject_deletemarker)
    run_test(test_b_uploadpartcopy_deletemarker)
    run_test(test_b2_uploadpart_deletemarker)
    run_test(test_c_getobjectacl_deletemarker)

    # PutObjectACL needs ACL-enabled bucket
    # On stage, try using the main bucket (ACL may already work)
    acl_bucket_created = False
    if TARGET != "stage":
        try:
            create_acl_bucket()
            acl_bucket_created = True
        except Exception as e:
            print(f"\n  !!! Failed to create ACL bucket: {e}")
    else:
        # On stage, use main bucket for PutObjectACL
        globals()["ACL_BUCKET"] = BUCKET
        # Try to get owner ID
        try:
            resp = s3.get_bucket_acl(Bucket=BUCKET)
            globals()["OWNER_ID"] = resp["Owner"]["ID"]
        except Exception:
            globals()["OWNER_ID"] = "test"

    try:
        run_test(test_d_putobjectacl_deletemarker)

        # Part 2: Control (real objects)
        print("\n>>> PART 2: CONTROL — REAL OBJECTS <<<")
        run_test(test_e_copyobject_real)
        run_test(test_f_uploadpartcopy_real)
        run_test(test_f2_uploadpart_real)
        run_test(test_g_getobjectacl_real)
        run_test(test_h_putobjectacl_real)

        # Part 3: Invalid versionId
        print("\n>>> PART 3: INVALID VERSION IDs <<<")
        run_test(test_i_copyobject_invalid_versionid)
        run_test(test_j_uploadpartcopy_invalid_versionid)
        run_test(test_j2_uploadpart_invalid_versionid)
        run_test(test_k_getobjectacl_invalid_versionid)
        run_test(test_l_putobjectacl_invalid_versionid)
    finally:
        if acl_bucket_created:
            delete_acl_bucket()

    # Write results to md
    suffix = f"_{TARGET}" if TARGET != "aws" else ""
    output_file = os.path.join(os.path.dirname(__file__), "..", f"versioning_mix{suffix}.md")

    results_text = f"""# Versioning Mix: DeleteMarker as Source — Reverse Engineering (AWS)

**Target:** {TARGET}
**Bucket:** {BUCKET}
**Region:** {REGION}
**Endpoint:** {ENDPOINT}

---

## Ключевые находки

_(заполняется после анализа результатов)_

---

## Тест-кейсы

### Part 1: DeleteMarker tests

**A. CopyObject — source is DeleteMarker**
- **A1** — source ONLY DM, без versionId
- **A2** — source ONLY DM, versionId=DM
- **A3** — source versions+DM, без versionId (latest=DM)
- **A4** — source versions+DM, versionId=DM

**B. UploadPartCopy — source is DeleteMarker**
- **B1** — source versions+DM, без versionId (latest=DM)
- **B2** — source versions+DM, versionId=DM
- **B3** — source ONLY DM, без versionId

**B2. UploadPart — dest key is DeleteMarker**
- **B2a** — dest key has versions+DM
- **B2b** — dest key is ONLY DM

**C. GetObjectACL — target is DeleteMarker**
- **C1** — versions+DM, без versionId (latest=DM)
- **C2** — ONLY DM, без versionId
- **C3** — versions+DM, versionId=DM
- **C4** — ONLY DM, versionId=DM

**D. PutObjectACL — target is DeleteMarker**
- **D1** — versions+DM, без versionId (latest=DM)
- **D2** — ONLY DM, без versionId
- **D3** — versions+DM, versionId=DM
- **D4** — ONLY DM, versionId=DM

### Part 2: Control — real objects (no delete markers)

**E. CopyObject** — E1 без versionId, E2 с versionId
**F. UploadPartCopy** — F1 без versionId, F2 с versionId
**F2. UploadPart** — F2a existing key, F2b new key
**G. GetObjectACL** — G1 без versionId, G2 с versionId
**H. PutObjectACL** — H1 без versionId, H2 с versionId

### Part 3: Invalid versionId (empty, "abc")

**I. CopyObject** — I1 versionId= (empty), I2 versionId=abc
**J. UploadPartCopy** — J1 versionId= (empty), J2 versionId=abc
**J2. UploadPart** — J2a versionId= (empty), J2b versionId=abc, J2c versionId=real
**K. GetObjectACL** — K1 versionId= (empty), K2 versionId=abc
**L. PutObjectACL** — L1 versionId= (empty), L2 versionId=abc

---

## Результаты

"""

    for test_id, desc, status, body, extra in RESULTS:
        results_text += f"\n### {test_id}: {desc}\n"
        if extra:
            results_text += f"**Info:** `{extra}`\n\n"
        results_text += f"**Status:** {status}\n"
        results_text += f"```\n{body}\n```\n"

    with open(output_file, "w") as f:
        f.write(results_text)

    print(f"\n\n{'='*70}")
    print(f"Done! Results written to {output_file}")
    print(f"Total tests: {len(RESULTS)}")
