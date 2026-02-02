"""Consolidated utilities for S3 compliance testing.

This module replaces duplicated code across test files.
"""

import base64
import hashlib
from typing import Union
from urllib.parse import quote

import requests


def calculate_content_md5(content: Union[str, bytes]) -> str:
    """Calculate Content-MD5 header value (base64 encoded).

    Args:
        content: Request body as string or bytes

    Returns:
        Base64-encoded MD5 hash
    """
    if isinstance(content, str):
        content = content.encode("utf-8")
    md5_hash = hashlib.md5(content).digest()
    return base64.b64encode(md5_hash).decode("utf-8")


def calculate_content_sha256(content: Union[str, bytes]) -> str:
    """Calculate x-amz-content-sha256 header value (hex encoded).

    Args:
        content: Request body as string or bytes

    Returns:
        Hex-encoded SHA256 hash
    """
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def base64_to_hex(b64_string: str) -> str:
    """Convert base64 to hex representation."""
    try:
        decoded = base64.b64decode(b64_string)
        return decoded.hex()
    except Exception:
        return b64_string


def url_encode_key(key: Union[str, bytes], safe: str = "") -> str:
    """URL-encode an S3 object key.

    Handles both string and bytes keys (for non-UTF-8 keys).

    Args:
        key: Object key as string or bytes
        safe: Characters to not encode (default: none)

    Returns:
        URL-encoded key
    """
    if isinstance(key, str):
        key = key.encode("utf-8")
    return quote(key, safe=safe)


def format_request_info(
    method: str,
    url: str,
    headers: dict,
    body: bytes,
    max_body_display: int = 2000,
) -> dict:
    """Format request information for logging/reporting.

    Args:
        method: HTTP method
        url: Request URL
        headers: Request headers
        body: Request body as bytes
        max_body_display: Maximum body characters to include

    Returns:
        dict with formatted request info
    """
    body_str = body.decode("utf-8", errors="replace") if body else ""
    return {
        "method": method,
        "url": url,
        "headers": dict(headers),
        "body": body_str[:max_body_display],
        "body_truncated": len(body_str) > max_body_display,
        "body_length": len(body) if body else 0,
    }


def format_response_info(
    response: requests.Response,
    max_body_display: int = 5000,
) -> dict:
    """Format response information for logging/reporting.

    Args:
        response: requests.Response object
        max_body_display: Maximum body characters to include

    Returns:
        dict with formatted response info
    """
    return {
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "body": response.text[:max_body_display],
        "body_truncated": len(response.text) > max_body_display,
        "body_length": len(response.content),
    }


def print_request_info(
    method: str,
    url: str,
    headers: dict,
    body: bytes,
    max_body_display: int = 2000,
) -> None:
    """Print request information to console.

    Args:
        method: HTTP method
        url: Request URL
        headers: Request headers
        body: Request body as bytes
        max_body_display: Maximum body characters to display
    """
    print(f"\n{'='*80}")
    print("REQUEST")
    print(f"{'='*80}")
    print(f"Method: {method}")
    print(f"URL: {url}")
    print("\nHeaders:")
    for key, value in headers.items():
        if len(str(value)) > 200:
            print(f"  {key}: {str(value)[:200]}... (truncated)")
        else:
            print(f"  {key}: {value}")

    if body:
        body_str = body.decode("utf-8", errors="replace")
        print(f"\nBody ({len(body)} bytes):")
        if len(body_str) <= max_body_display:
            print(body_str)
        else:
            print(body_str[:max_body_display])
            print(f"\n... (truncated, {len(body_str) - max_body_display} chars omitted) ...")


def print_response_info(
    response: requests.Response,
    max_body_display: int = 5000,
) -> None:
    """Print response information to console.

    Args:
        response: requests.Response object
        max_body_display: Maximum body characters to display
    """
    print(f"\n{'='*80}")
    print("RESPONSE")
    print(f"{'='*80}")
    print(f"Status Code: {response.status_code}")
    print("\nResponse Headers:")
    for key, value in response.headers.items():
        if len(str(value)) > 200:
            print(f"  {key}: {str(value)[:200]}... (truncated)")
        else:
            print(f"  {key}: {value}")

    print(f"\nResponse Body ({len(response.content)} bytes):")
    response_text = response.text
    if len(response_text) <= max_body_display:
        print(response_text)
    else:
        print(response_text[:max_body_display])
        print(f"\n... (truncated, {len(response_text) - max_body_display} chars omitted) ...")
        print(response_text[-1000:])
