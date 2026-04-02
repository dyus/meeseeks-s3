#!/usr/bin/env python3
"""Send Unicode validation order test requests to AWS S3 and print results.

Determines where Unicode characters in key-marker, version-id-marker, and prefix
sit in the S3 validation pipeline.
"""

import hashlib
import os
import sys
import urllib.parse
import xml.etree.ElementTree as ET

import boto3
import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

REGION = os.getenv("AWS_REGION", "us-east-1")
PROFILE = os.getenv("AWS_PROFILE", "default")
BUCKET = os.getenv("S3_TEST_BUCKET", "anon-reverse-s3-test-bucket")

ENDPOINT = f"https://s3.{REGION}.amazonaws.com"

session = boto3.Session(profile_name=PROFILE, region_name=REGION)
credentials = session.get_credentials().get_frozen_credentials()

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def signed_get(path_and_query: str) -> requests.Response:
    """Send a signed GET request to S3 with proper SigV4 signing."""
    url = f"{ENDPOINT}{path_and_query}"
    headers = {
        "x-amz-content-sha256": EMPTY_SHA256,
        "Content-Length": "0",
    }
    aws_req = AWSRequest(method="GET", url=url, headers=headers, data=b"")
    SigV4Auth(credentials, "s3", REGION).add_auth(aws_req)
    signed = dict(aws_req.headers)
    # Use a session with no retries, send the exact URL without re-encoding
    s = requests.Session()
    req = requests.Request("GET", url, headers=signed)
    prepared = req.prepare()
    # Preserve our URL exactly (requests may re-encode)
    prepared.url = url
    return s.send(prepared, timeout=30)


def build_query(**params) -> str:
    """Build ?versions&key-marker=...&... query string."""
    parts = ["versions"]
    for k, v in params.items():
        encoded = urllib.parse.quote(str(v), safe="")
        parts.append(f"{k}={encoded}")
    return "?" + "&".join(parts)


def parse_error(text: str) -> tuple[str | None, str | None]:
    """Extract Code and Message from S3 error XML."""
    try:
        root = ET.fromstring(text)
        code = root.findtext("Code")
        msg = root.findtext("Message")
        return code, msg
    except ET.ParseError:
        return None, None


def parse_field(text: str, tag: str) -> str | None:
    """Extract a field from ListVersionsResult XML."""
    ns = "http://s3.amazonaws.com/doc/2006-03-01/"
    try:
        root = ET.fromstring(text)
        el = root.find(f"{{{ns}}}{tag}")
        return el.text if el is not None else None
    except ET.ParseError:
        return None


# Unicode test characters
CHARS = {
    "中 (CJK)": "\u4e2d",
    "🔑 (emoji)": "\U0001f511",
    "é (latin)": "\u00e9",
}

results = []


def run_test(name: str, path_query: str, expect_field: str = None):
    """Run a single test and collect results."""
    resp = signed_get(path_query)
    status = resp.status_code
    if status == 200:
        echo_val = parse_field(resp.text, expect_field) if expect_field else None
        results.append({
            "name": name,
            "status": status,
            "error_code": None,
            "error_message": None,
            "echo": echo_val,
            "query": path_query.split("?", 1)[1] if "?" in path_query else "",
            "response_xml": None,
        })
    else:
        code, msg = parse_error(resp.text)
        results.append({
            "name": name,
            "status": status,
            "error_code": code,
            "error_message": msg,
            "echo": None,
            "query": path_query.split("?", 1)[1] if "?" in path_query else "",
            "response_xml": resp.text,
        })


print(f"Bucket: {BUCKET}")
print(f"Region: {REGION}")
print()

# ==========================================
# Part 1: Standalone Unicode tests
# ==========================================
print("=" * 80)
print("PART 1: Standalone Unicode tests")
print("=" * 80)

for char_name, char in CHARS.items():
    # key-marker
    q = build_query(**{"key-marker": char, "max-keys": "1"})
    run_test(f"key-marker={char_name}", f"/{BUCKET}{q}", "KeyMarker")

    # prefix
    q = build_query(prefix=char, **{"max-keys": "1"})
    run_test(f"prefix={char_name}", f"/{BUCKET}{q}", "Prefix")

    # version-id-marker (with key-marker)
    q = build_query(**{"key-marker": "some-key", "version-id-marker": char, "max-keys": "1"})
    run_test(f"vid={char_name} (key=some-key)", f"/{BUCKET}{q}")

print()
for r in results:
    if r["status"] == 200:
        print(f"  ✓ {r['name']}: {r['status']} (echo={r['echo']!r})")
    else:
        print(f"  ✗ {r['name']}: {r['status']} → {r['error_code']}: {r['error_message']}")

# ==========================================
# Part 2: Validation order — pairwise tests
# ==========================================
print()
print("=" * 80)
print("PART 2: Unicode validation order (pairwise)")
print("=" * 80)

pair_results = []


def run_pair(name: str, pair_desc: str, path_query: str):
    resp = signed_get(path_query)
    code, msg = parse_error(resp.text) if resp.status_code != 200 else (None, None)

    # Determine winner
    if resp.status_code == 200:
        winner = "ACCEPTED (200)"
    elif msg and "max-keys" in msg.lower():
        winner = "max-keys"
    elif msg and "cannot be empty" in msg.lower():
        winner = "empty-vid"
    elif msg and "without a key" in msg.lower():
        winner = "dependency"
    elif msg and "invalid version id" in msg.lower():
        winner = "vid-format"
    elif msg and "encoding" in msg.lower():
        winner = "encoding-type"
    else:
        winner = f"unknown ({msg})"

    entry = {
        "name": name,
        "pair": pair_desc,
        "status": resp.status_code,
        "error_code": code,
        "error_message": msg,
        "winner": winner,
        "query": path_query.split("?", 1)[1] if "?" in path_query else "",
        "response_xml": resp.text if resp.status_code != 200 else None,
    }
    pair_results.append(entry)
    return entry


# P8: Unicode vid + invalid max-keys
q = build_query(**{"key-marker": "k", "version-id-marker": "\U0001f511", "max-keys": "abc"})
run_pair("P8", "unicode-vid(🔑) + max-keys=abc", f"/{BUCKET}{q}")

# P9: Unicode vid + invalid encoding
q = build_query(**{"key-marker": "k", "version-id-marker": "\u4e2d", "encoding-type": "invalid"})
run_pair("P9", "unicode-vid(中) + encoding=invalid", f"/{BUCKET}{q}")

# P10: Unicode vid without key-marker (dependency check)
q = build_query(**{"version-id-marker": "\u00e9"})
run_pair("P10", "unicode-vid(é) without key-marker", f"/{BUCKET}{q}")

# P11: Unicode key-marker + invalid encoding
q = build_query(**{"key-marker": "\u4e2d", "encoding-type": "invalid"})
run_pair("P11", "unicode-key(中) + encoding=invalid", f"/{BUCKET}{q}")

# P12: Unicode prefix + invalid encoding
q = build_query(prefix="\U0001f511", **{"encoding-type": "invalid"})
run_pair("P12", "unicode-prefix(🔑) + encoding=invalid", f"/{BUCKET}{q}")

# P13: Unicode prefix + invalid max-keys
q = build_query(prefix="\u00e9", **{"max-keys": "abc"})
run_pair("P13", "unicode-prefix(é) + max-keys=abc", f"/{BUCKET}{q}")

# P14: Unicode key-marker + invalid max-keys
q = build_query(**{"key-marker": "\U0001f511", "max-keys": "abc"})
run_pair("P14", "unicode-key(🔑) + max-keys=abc", f"/{BUCKET}{q}")

# P15: Unicode key + Unicode vid + invalid encoding
q = build_query(**{"key-marker": "\u4e2d", "version-id-marker": "\U0001f511", "encoding-type": "invalid"})
run_pair("P15", "unicode-key(中) + unicode-vid(🔑) + encoding=invalid", f"/{BUCKET}{q}")

# P16: All Unicode + invalid max-keys
q = build_query(**{"key-marker": "\u4e2d", "version-id-marker": "\U0001f511", "max-keys": "abc"}, prefix="\u00e9")
run_pair("P16", "unicode-key(中) + unicode-vid(🔑) + unicode-prefix(é) + max-keys=abc", f"/{BUCKET}{q}")

# P17: Unicode vid + empty-vid (vid="" with key) — is Unicode vid treated as empty?
# (it shouldn't be — it has content, just not ASCII)
# Already tested standalone. Let's add: unicode vid without key vs unicode vid with key
# P17: Unicode vid + dependency + encoding all at once
q = build_query(**{"version-id-marker": "\U0001f511", "encoding-type": "invalid"})
run_pair("P17", "unicode-vid(🔑) without key + encoding=invalid", f"/{BUCKET}{q}")

# P18: Unicode vid without key + invalid max-keys
q = build_query(**{"version-id-marker": "\u4e2d", "max-keys": "abc"})
run_pair("P18", "unicode-vid(中) without key + max-keys=abc", f"/{BUCKET}{q}")

print()
print(f"{'Test':<6} | {'Status':<6} | {'Winner':<15} | Pair")
print("-" * 80)
for r in pair_results:
    print(f"{r['name']:<6} | {r['status']:<6} | {r['winner']:<15} | {r['pair']}")

# ==========================================
# Part 3: Summary table
# ==========================================
print()
print("=" * 80)
print("VALIDATION ORDER PROOF (including Unicode)")
print("=" * 80)
print()
print("| Тест | Пара | Победитель | Доказывает |")
print("|------|------|-----------|------------|")
for r in pair_results:
    proves = ""
    w = r["winner"]
    if w == "max-keys":
        proves = "max-keys > всё остальное"
    elif w == "dependency":
        proves = "dependency > vid-format, encoding"
    elif w == "vid-format":
        proves = "vid-format > encoding"
    elif w == "encoding-type":
        proves = "encoding > unicode key/prefix (валидны)"
    elif w == "ACCEPTED (200)":
        proves = "оба параметра валидны"
    else:
        proves = f"? ({w})"
    print(f"| {r['name']} | {r['pair']} | **{w}** | {proves} |")

# ==========================================
# Part 4: Full XML responses for documentation
# ==========================================
print()
print("=" * 80)
print("FULL RESPONSES FOR DOCUMENTATION")
print("=" * 80)

# Print standalone results
for r in results:
    print()
    print(f"## {r['name']}")
    print()
    print(f"**Запрос:** `GET /{BUCKET}?{r['query']}`")
    print()
    if r["status"] == 200:
        print(f"| | Тест |")
        print(f"|---|---|")
        print(f"| Status | **{r['status']}** |")
        if r["echo"]:
            print(f"| Echo | `{r['echo']}` |")
        print()
        print("_(200 OK — XML response omitted for brevity)_")
    else:
        print(f"| | Тест |")
        print(f"|---|---|")
        print(f"| Status | **{r['status']}** |")
        print(f"| Error Code | **{r['error_code']}** |")
        print(f"| Error Message | **{r['error_message']}** |")
        print()
        print("```xml")
        # Pretty-print the XML
        try:
            root = ET.fromstring(r["response_xml"])
            ET.indent(root, space="  ")
            print(ET.tostring(root, encoding="unicode"))
        except Exception:
            print(r["response_xml"])
        print("```")

# Print pair results
for r in pair_results:
    print()
    print(f"## {r['name']}. Порядок: {r['pair']}")
    print()
    print(f"| | Тест |")
    print(f"|---|---|")
    print(f"| Status | **{r['status']}** |")
    if r["error_code"]:
        print(f"| Error Code | **{r['error_code']}** |")
    if r["error_message"]:
        print(f"| Error Message | **{r['error_message']}** |")
    print()
    print(f"**Запрос:** `GET /{BUCKET}?{r['query']}`")
    print()
    if r["response_xml"]:
        print("**Ответ:**")
        print()
        print("```xml")
        try:
            root = ET.fromstring(r["response_xml"])
            ET.indent(root, space="  ")
            print(ET.tostring(root, encoding="unicode"))
        except Exception:
            print(r["response_xml"])
        print("```")
    print()
    print("---")
