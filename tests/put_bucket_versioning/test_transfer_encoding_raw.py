"""Tests for PutBucketVersioning Transfer-Encoding using raw HTTP (http.client).

These tests bypass the `requests` library which interferes with
Transfer-Encoding: it applies real chunked encoding, adds Content-Length,
or resets connections. Using http.client directly gives full control over
headers and body bytes sent over the wire.

Covers TE table rows 1, 10, 16 from putbucketversioning.md that showed
discrepancies when tested through the `requests` library:
  - Row 1:  TE: chunked / empty body → expected 400
  - Row 10: TE: compress, chunked / empty body → expected ConnectionReset
  - Row 16: TE: chunked / valid body → expected 200 (versioning applied)

Supports --endpoint=aws (raw HTTP tests always target a single endpoint).
"""

import http.client
import ssl
from urllib.parse import urlparse

import pytest

from s3_compliance.signing import sign_request
from s3_compliance.utils import calculate_content_sha256
from s3_compliance.client import S3ClientFactory
from s3_compliance.xml_utils import extract_error_info


def _chunked_encode(body: bytes) -> bytes:
    """Encode body in HTTP chunked transfer encoding format.

    Format: <hex size>\\r\\n<data>\\r\\n ... 0\\r\\n\\r\\n
    """
    if not body:
        return b"0\r\n\r\n"
    chunk = f"{len(body):x}\r\n".encode() + body + b"\r\n"
    return chunk + b"0\r\n\r\n"


def _raw_https_request(
    method: str,
    url: str,
    headers: dict,
    raw_body: bytes,
    timeout: float = 30.0,
):
    """Send a raw HTTPS request with exact headers and body bytes.

    Does NOT interpret Transfer-Encoding — sends raw_body as-is after headers.
    Host header MUST be present in headers dict.

    Returns:
        (status_code, resp_headers_dict, resp_body_str) on success.

    Raises:
        ConnectionError / OSError on connection reset.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path
    if parsed.query:
        path += "?" + parsed.query

    if parsed.scheme == "https":
        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        for key, value in headers.items():
            conn.putheader(key, value)
        # Pass body via endheaders to send headers + body in one shot
        conn.endheaders(raw_body)

        response = conn.getresponse()
        status = response.status
        resp_headers = dict(response.getheaders())
        resp_body = response.read().decode("utf-8", errors="replace")
        return status, resp_headers, resp_body
    finally:
        conn.close()


@pytest.fixture(scope="module")
def aws_setup():
    """Provide AWS endpoint URL, credentials, region, and host header value."""
    factory = S3ClientFactory()
    url = factory.get_endpoint_url("aws")
    return {
        "url": url,
        "host": urlparse(url).hostname,
        "creds": factory.get_credentials("aws"),
        "region": factory.get_region("aws"),
    }


def _sign(aws_setup, method, url, headers, body):
    """Sign request and return signed headers dict.

    Adds Host header before signing (required by SigV4 but not returned
    by botocore's sign_request when using AWSRequest).
    """
    h = dict(headers)
    h.setdefault("Host", aws_setup["host"])
    return sign_request(
        method=method,
        url=url,
        headers=h,
        body=body,
        credentials=aws_setup["creds"],
        region=aws_setup["region"],
    )


VERSIONING_XML = (
    b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    b"<Status>Enabled</Status>"
    b"<MfaDelete>Disabled</MfaDelete>"
    b"</VersioningConfiguration>"
)


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestTransferEncodingRaw:
    """Transfer-Encoding tests using raw http.client (no requests lib)."""

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_te_chunked_empty_body_raw(
        self, test_bucket, aws_setup, json_metadata
    ):
        """TE: chunked with empty body → 400 MissingRequestBodyError (doc TE row 1).

        Sends proper chunked-encoded empty body (just terminator '0\\r\\n\\r\\n').
        Signs with empty body hash, no Content-Length header.
        """
        original_body = b""
        url = f"{aws_setup['url']}/{test_bucket}?versioning"

        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "chunked",
            "x-amz-content-sha256": calculate_content_sha256(original_body),
        }
        signed = _sign(aws_setup, "PUT", url, headers, original_body)
        signed.pop("Content-Length", None)

        raw_body = _chunked_encode(original_body)

        json_metadata["transfer_encoding"] = "chunked"
        json_metadata["body"] = "empty"
        json_metadata["transport"] = "raw http.client"

        status, _, resp_body = _raw_https_request("PUT", url, signed, raw_body)

        json_metadata["status"] = status
        if status >= 400:
            error_code, error_msg = extract_error_info(resp_body)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

        assert status == 400, f"Expected 400, got {status}: {resp_body[:200]}"

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_te_compress_chunked_empty_body_raw(
        self, test_bucket, aws_setup, json_metadata
    ):
        """TE: compress, chunked with empty body (doc TE row 10).

        Document expects ConnectionResetError.
        """
        original_body = b""
        url = f"{aws_setup['url']}/{test_bucket}?versioning"

        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "compress, chunked",
            "x-amz-content-sha256": calculate_content_sha256(original_body),
        }
        signed = _sign(aws_setup, "PUT", url, headers, original_body)
        signed.pop("Content-Length", None)

        raw_body = _chunked_encode(original_body)

        json_metadata["transfer_encoding"] = "compress, chunked"
        json_metadata["body"] = "empty"
        json_metadata["transport"] = "raw http.client"

        try:
            status, _, resp_body = _raw_https_request("PUT", url, signed, raw_body)
            json_metadata["status"] = status
            if status >= 400:
                error_code, _ = extract_error_info(resp_body)
                json_metadata["error_code"] = error_code
        except (ConnectionError, ConnectionResetError, BrokenPipeError, OSError) as exc:
            json_metadata["result"] = f"ConnectionError: {type(exc).__name__}"

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_te_chunked_valid_body_raw(
        self, test_bucket, aws_setup, json_metadata
    ):
        """TE: chunked with valid versioning XML → 200 (doc TE row 16).

        Sends proper chunked-encoded body with valid XML.
        Signs with original body hash, no Content-Length header.
        """
        original_body = VERSIONING_XML
        url = f"{aws_setup['url']}/{test_bucket}?versioning"

        headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "chunked",
            "x-amz-content-sha256": calculate_content_sha256(original_body),
        }
        signed = _sign(aws_setup, "PUT", url, headers, original_body)
        signed.pop("Content-Length", None)

        raw_body = _chunked_encode(original_body)

        json_metadata["transfer_encoding"] = "chunked"
        json_metadata["body"] = "valid_xml"
        json_metadata["transport"] = "raw http.client"

        try:
            status, _, resp_body = _raw_https_request("PUT", url, signed, raw_body)
            json_metadata["status"] = status
            assert status == 200, f"Expected 200, got {status}: {resp_body[:200]}"
        except (ConnectionError, ConnectionResetError, BrokenPipeError, OSError) as exc:
            json_metadata["result"] = f"ConnectionError: {type(exc).__name__}"
            pytest.fail(f"Connection error: {type(exc).__name__}: {exc}")

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_te_chunked_valid_body_verify_applied(
        self, test_bucket, aws_setup, json_metadata
    ):
        """TE: chunked with valid body → verify versioning was actually applied.

        Suspends versioning, re-enables via chunked request,
        checks GetBucketVersioning to confirm the state changed.
        """
        url_versioning = f"{aws_setup['url']}/{test_bucket}?versioning"

        # Step 1: Suspend versioning (plain request)
        suspend_body = (
            b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            b"<Status>Suspended</Status>"
            b"<MfaDelete>Disabled</MfaDelete>"
            b"</VersioningConfiguration>"
        )
        suspend_headers = {
            "Content-Type": "application/xml",
            "Content-Length": str(len(suspend_body)),
            "x-amz-content-sha256": calculate_content_sha256(suspend_body),
        }
        signed_suspend = _sign(aws_setup, "PUT", url_versioning, suspend_headers, suspend_body)
        status, _, body = _raw_https_request("PUT", url_versioning, signed_suspend, suspend_body)
        assert status == 200, f"Suspend setup failed: {status}: {body[:200]}"

        # Step 2: Enable via chunked TE
        enable_headers = {
            "Content-Type": "application/xml",
            "Transfer-Encoding": "chunked",
            "x-amz-content-sha256": calculate_content_sha256(VERSIONING_XML),
        }
        signed_enable = _sign(aws_setup, "PUT", url_versioning, enable_headers, VERSIONING_XML)
        signed_enable.pop("Content-Length", None)

        try:
            status, _, resp_body = _raw_https_request(
                "PUT", url_versioning, signed_enable, _chunked_encode(VERSIONING_XML)
            )
        except (ConnectionError, OSError) as exc:
            pytest.skip(f"Chunked request failed: {type(exc).__name__}: {exc}")

        json_metadata["chunked_put_status"] = status
        if status != 200:
            pytest.skip(f"Chunked PUT returned {status}, cannot verify")

        # Step 3: GET ?versioning to verify
        get_headers = {
            "x-amz-content-sha256": calculate_content_sha256(b""),
        }
        signed_get = _sign(aws_setup, "GET", url_versioning, get_headers, b"")
        get_status, _, get_body = _raw_https_request("GET", url_versioning, signed_get, b"")

        assert get_status == 200, f"GET ?versioning failed: {get_status}"
        assert "<Status>Enabled</Status>" in get_body, (
            f"Versioning not applied via chunked TE. Body: {get_body[:300]}"
        )
        json_metadata["verified"] = True
