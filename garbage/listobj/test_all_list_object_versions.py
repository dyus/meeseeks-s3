#!/usr/bin/env python3
"""
Test all ListObjectVersions cases and generate a markdown report with raw XML responses.

Usage:
    python3 test_all_list_object_versions.py

Environment variables:
    AWS_REGION (default: us-east-1)
    AWS_PROFILE (default: from ~/.aws/credentials)
    S3_ENDPOINT_URL (optional: custom endpoint)
    TEST_BUCKET_NAME (default: test-dagm-bucket-listversioning)
"""

import hashlib
import os
import sys
import tempfile
import time
import uuid
import xml.dom.minidom
from datetime import datetime
from urllib.parse import quote, urlencode

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import requests


BUCKET_NAME = os.environ.get("TEST_BUCKET_NAME", "test-dagm-bucket-listversioning")
REGION = os.environ.get("AWS_REGION", "us-east-1")
ENDPOINT_URL = os.environ.get("S3_ENDPOINT_URL", "")
OBJECTS = ["a", "aa", "a/as", "a/", "a/f", "b", "b/", "c", "d"]
OBJECTS_WITH_VERSIONS = ["a", "aa", "a/as", "a/", "b", "b/", "a/f"]
# Objects to delete (creates delete markers)
OBJECTS_TO_DELETE = ["c", "d"]
# Object to delete and re-create (delete marker in the middle)
OBJECT_REVIVE = "b/"


def get_session():
    profile = os.environ.get("AWS_PROFILE", None)
    return boto3.Session(profile_name=profile, region_name=REGION)


def get_s3_client(session):
    kwargs = {"region_name": REGION}
    if ENDPOINT_URL:
        kwargs["endpoint_url"] = ENDPOINT_URL
    return session.client("s3", **kwargs)


def make_signed_request(session, method, url, headers=None):
    """Make a signed request and return (status, response_headers, body_text)."""
    if headers is None:
        headers = {}
    body_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    headers["x-amz-content-sha256"] = body_hash

    aws_request = AWSRequest(method=method, url=url, headers=headers)
    credentials = session.get_credentials().get_frozen_credentials()
    SigV4Auth(credentials, "s3", REGION).add_auth(aws_request)

    resp = requests.request(
        method=method,
        url=url,
        headers=dict(aws_request.headers),
    )
    return resp.status_code, dict(resp.headers), resp.text


def base_url():
    if ENDPOINT_URL:
        return f"{ENDPOINT_URL.rstrip('/')}/{BUCKET_NAME}"
    return f"https://{BUCKET_NAME}.s3.{REGION}.amazonaws.com"


def pretty_xml(raw):
    """Pretty-print XML, return as string. Falls back to raw if invalid."""
    try:
        dom = xml.dom.minidom.parseString(raw)
        pretty = dom.toprettyxml(indent="  ")
        # Remove the xml declaration line if present
        lines = pretty.split("\n")
        if lines[0].startswith("<?xml"):
            return "\n".join(lines[1:]).strip()
        return pretty.strip()
    except Exception:
        return raw


def run_test(session, test_id, description, query_params):
    """Run a single test, return dict with results."""
    params = {"versions": ""}
    params.update(query_params)
    params_str = urlencode(params, quote_via=quote, doseq=True)
    url = f"{base_url()}/?{params_str}"

    try:
        status, resp_headers, body = make_signed_request(session, "GET", url)
    except (requests.exceptions.ConnectionError, ConnectionResetError, OSError) as exc:
        return {
            "id": test_id,
            "description": description,
            "query_params": query_params,
            "url": url,
            "status": -1,
            "headers": {},
            "body": f"ConnectionError: {type(exc).__name__}: {exc}",
        }

    return {
        "id": test_id,
        "description": description,
        "query_params": query_params,
        "url": url,
        "status": status,
        "headers": resp_headers,
        "body": body,
    }


def format_test_md(result):
    """Format a single test result as markdown."""
    md = []
    md.append(f"## {result['id']}. {result['description']}\n")
    md.append(f"| | Тест |")
    md.append(f"|---|---|")
    if result["status"] == -1:
        md.append(f"| Status | **ConnectionError** |")
    else:
        md.append(f"| Status | **{result['status']}** |")

    body = result["body"]
    if result["status"] == -1:
        pass  # No XML to parse
    elif result["status"] >= 400:
        # Extract error info
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(body)
            code = root.findtext("Code") or root.findtext("{http://s3.amazonaws.com/doc/2006-03-01/}Code")
            msg = root.findtext("Message") or root.findtext("{http://s3.amazonaws.com/doc/2006-03-01/}Message")
            if code:
                md.append(f"| Error Code | **{code}** |")
            if msg:
                md.append(f"| Error Message | **{msg}** |")
        except Exception:
            pass
    else:
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(body)
            ns = "http://s3.amazonaws.com/doc/2006-03-01/"
            max_keys = root.findtext(f"{{{ns}}}MaxKeys")
            is_truncated = root.findtext(f"{{{ns}}}IsTruncated")
            next_key = root.findtext(f"{{{ns}}}NextKeyMarker")
            versions = root.findall(f"{{{ns}}}Version")
            markers = root.findall(f"{{{ns}}}DeleteMarker")
            prefixes = root.findall(f".//{{{ns}}}CommonPrefixes/{{{ns}}}Prefix")
            delimiter = root.findtext(f"{{{ns}}}Delimiter")
            if max_keys:
                md.append(f"| MaxKeys | {max_keys} |")
            if is_truncated:
                md.append(f"| IsTruncated | {is_truncated} |")
            if next_key:
                md.append(f"| NextKeyMarker | `{next_key}` |")
            if delimiter is not None:
                md.append(f"| Delimiter | `{delimiter}` |")
            md.append(f"| Versions | {len(versions)} |")
            md.append(f"| DeleteMarkers | {len(markers)} |")
            if prefixes:
                md.append(f"| CommonPrefixes | {len(prefixes)} |")
        except Exception:
            pass

    md.append("")

    # Query params
    if result["query_params"]:
        params_display = "&".join(f"{k}={v}" for k, v in result["query_params"].items())
        md.append(f"**Запрос:** `GET /{{bucket}}?versions&{params_display}`\n")
    else:
        md.append(f"**Запрос:** `GET /{{bucket}}?versions`\n")

    md.append("**Ответ:**\n")
    md.append("```xml")
    md.append(pretty_xml(body))
    md.append("```\n")
    md.append("---\n")
    return "\n".join(md)


def setup_bucket(s3_client):
    """Create bucket, objects, enable versioning, add versions."""
    # Create bucket
    try:
        s3_client.create_bucket(Bucket=BUCKET_NAME)
    except Exception as e:
        if "BucketAlreadyOwnedByYou" not in str(e) and "BucketAlreadyExists" not in str(e):
            print(f"Warning: {e}")

    # Create objects (pre-versioning, will get VersionId=null)
    for key in OBJECTS:
        s3_client.put_object(Bucket=BUCKET_NAME, Key=key, Body=f"Content for {key}\n".encode())

    # Enable versioning
    s3_client.put_bucket_versioning(
        Bucket=BUCKET_NAME,
        VersioningConfiguration={"Status": "Enabled"},
    )

    # Add extra versions
    for key in OBJECTS_WITH_VERSIONS:
        for v in [2, 3]:
            s3_client.put_object(Bucket=BUCKET_NAME, Key=key, Body=f"Version {v} for {key}\n".encode())

    # Delete some objects to create delete markers
    for key in OBJECTS_TO_DELETE:
        s3_client.delete_object(Bucket=BUCKET_NAME, Key=key)
    print(f"  Created delete markers for: {OBJECTS_TO_DELETE}")

    # Revive one object: delete then re-put (delete marker in the middle of version history)
    s3_client.delete_object(Bucket=BUCKET_NAME, Key=OBJECT_REVIVE)
    s3_client.put_object(Bucket=BUCKET_NAME, Key=OBJECT_REVIVE, Body=b"revived content\n")
    print(f"  Revived object: {OBJECT_REVIVE} (version -> delete marker -> version)")

    time.sleep(1)
    print(f"Setup complete: {BUCKET_NAME}, {len(OBJECTS)} objects, versioning enabled, delete markers created")


def main():
    session = get_session()
    s3_client = get_s3_client(session)

    setup_bucket(s3_client)

    results = []

    # ---- Error cases ----

    # 2. Invalid max-keys
    results.append(run_test(session, 2, "Невалидный max-keys", {"max-keys": "abc"}))

    # 3. Empty max-keys
    results.append(run_test(session, 3, "Пустой max-keys", {"max-keys": ""}))

    # 4. Invalid encoding-type
    results.append(run_test(session, 4, "Невалидный encoding-type", {"encoding-type": "invalid-encoding"}))

    # 5. Empty encoding-type
    results.append(run_test(session, 5, "Пустой encoding-type", {"encoding-type": "", "max-keys": "5"}))

    # 6. version-id-marker without key-marker
    results.append(run_test(session, 6, "version-id-marker без key-marker",
                            {"version-id-marker": "invalid-version-id-123"}))

    # 7. Empty version-id-marker with key-marker
    results.append(run_test(session, 7, "Пустой version-id-marker с key-marker",
                            {"key-marker": "ab", "version-id-marker": "", "max-keys": "1"}))

    # 8. Invalid version-id (random string)
    results.append(run_test(session, 8, "Невалидный version-id (random string)",
                            {"key-marker": "a", "version-id-marker": "nonexistent-version-id-12345", "max-keys": "1"}))

    # 9. Invalid version-id (similar format)
    results.append(run_test(session, 9, "Невалидный version-id (похожий формат)",
                            {"key-marker": "a", "version-id-marker": "Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R", "max-keys": "1"}))

    # 10. version-id-marker = null
    results.append(run_test(session, 10, "version-id-marker = null",
                            {"key-marker": "a", "version-id-marker": "null", "max-keys": "1"}))

    # ---- Success cases ----

    # 11. List all versions
    results.append(run_test(session, 11, "Листинг всех версий", {}))

    # 12. Pagination key-marker without version-id-marker
    results.append(run_test(session, 12, "Пагинация key-marker без version-id-marker",
                            {"key-marker": "ab", "max-keys": "1"}))

    # 13. Pagination with version-id-marker=null
    results.append(run_test(session, 13, "Пагинация key-marker + version-id-marker=null",
                            {"key-marker": "a", "version-id-marker": "null", "max-keys": "1"}))

    # 14. Delimiter with NextKeyMarker ending in /
    results.append(run_test(session, 14, "Delimiter с NextKeyMarker оканчивающимся на /",
                            {"delimiter": "/", "max-keys": "13"}))

    # 15. Delimiter with NextKeyMarker without /
    results.append(run_test(session, 15, "Delimiter с NextKeyMarker без /",
                            {"delimiter": "/", "max-keys": "1"}))

    # 16. Empty delimiter
    results.append(run_test(session, 16, "Пустой delimiter = отсутствие",
                            {"delimiter": "", "max-keys": "5"}))

    # 17. Empty prefix
    results.append(run_test(session, 17, "Пустой prefix = отсутствие",
                            {"prefix": "", "max-keys": "5"}))

    # 18. encoding-type=url
    results.append(run_test(session, 18, "encoding-type=url",
                            {"encoding-type": "url", "max-keys": "3"}))

    # 19. max-keys=0
    results.append(run_test(session, 19, "max-keys=0", {"max-keys": "0"}))

    # ---- Delete markers cases ----

    # 20. List deleted object (key-marker just before c, max-keys small)
    results.append(run_test(session, 20, "Удалённый объект — DeleteMarker как latest",
                            {"key-marker": "bz", "max-keys": "5"}))

    # 21. Revived object: version -> delete marker -> version
    results.append(run_test(session, 21, "Восстановленный объект — Version после DeleteMarker",
                            {"key-marker": "b.", "max-keys": "10"}))

    # 22. Mixed listing starting from key-marker=b to include delete markers
    results.append(run_test(session, 22, "Смешанный листинг — Versions и DeleteMarkers вместе",
                            {"key-marker": "b", "max-keys": "20"}))

    # ---- Validation order pairs ----

    # Pair 1: max-keys > empty-vid
    results.append(run_test(session, "P1", "Порядок: max-keys=abc + key=k,vid=\"\"",
                            {"max-keys": "abc", "key-marker": "k", "version-id-marker": ""}))

    # Pair 2: empty-vid > encoding
    results.append(run_test(session, "P2", "Порядок: key=k,vid=\"\" + encoding=invalid",
                            {"key-marker": "k", "version-id-marker": "", "encoding-type": "invalid"}))

    # Pair 3: empty-vid vs dependency (vid="" no key)
    results.append(run_test(session, "P3", "Порядок: vid=\"\" без key",
                            {"version-id-marker": ""}))

    # Pair 4: dependency > encoding
    results.append(run_test(session, "P4", "Порядок: vid=bad + encoding=invalid без key",
                            {"version-id-marker": "bad-vid", "encoding-type": "invalid"}))

    # Pair 5: vid format > encoding
    results.append(run_test(session, "P5", "Порядок: key=k,vid=bad + encoding=invalid",
                            {"key-marker": "k", "version-id-marker": "bad-vid", "encoding-type": "invalid"}))

    # Pair 6: max-keys > dependency
    results.append(run_test(session, "P6", "Порядок: max-keys=abc + vid=bad без key",
                            {"max-keys": "abc", "version-id-marker": "bad-vid"}))

    # Pair 7: dependency with empty key
    results.append(run_test(session, "P7", "Порядок: key=\"\"+vid=bad + encoding=invalid",
                            {"key-marker": "", "version-id-marker": "bad-vid", "encoding-type": "invalid"}))

    # ---- Generate report ----
    report = []
    report.append(f"# ListObjectVersions — результаты тестов\n")
    report.append(f"**Дата:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"**Region:** `{REGION}`")
    report.append(f"**Bucket:** `{BUCKET_NAME}`")
    if ENDPOINT_URL:
        report.append(f"**Endpoint:** `{ENDPOINT_URL}`")
    report.append("\n---\n")

    for r in results:
        report.append(format_test_md(r))

    # Write report
    output_file = "listobjectversioning_test_results.md"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write("\n".join(report))

    print(f"\n✓ Report saved to {output_file}")
    print(f"  Tests run: {len(results)}")
    errors = sum(1 for r in results if r['status'] >= 400)
    successes = sum(1 for r in results if r['status'] < 400)
    print(f"  Errors (expected): {errors}")
    print(f"  Successes: {successes}")


if __name__ == "__main__":
    main()
