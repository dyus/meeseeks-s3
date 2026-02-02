"""SigV4 signing utilities for S3 requests."""

from typing import Optional

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.session import Session


def get_credentials(profile_name: str = "aws") -> Optional[Credentials]:
    """Get AWS credentials from profile.

    Tries boto3 first, falls back to botocore Session.
    """
    try:
        session = boto3.Session(profile_name=profile_name)
        credentials = session.get_credentials()
        if credentials:
            return credentials
    except Exception:
        pass

    # Fallback to botocore Session
    try:
        session = Session(profile=profile_name)
        return session.get_credentials()
    except Exception:
        return None


def sign_request(
    method: str,
    url: str,
    headers: dict,
    body: bytes,
    credentials: Credentials,
    region: str,
    service: str = "s3",
    unsigned_payload: bool = False,
) -> dict:
    """Sign an HTTP request using SigV4Auth.

    Args:
        method: HTTP method (GET, PUT, POST, DELETE, etc.)
        url: Full URL of the request
        headers: Request headers (will be modified with auth headers)
        body: Request body as bytes
        credentials: AWS credentials
        region: AWS region
        service: AWS service name (default: s3)
        unsigned_payload: If True, use UNSIGNED-PAYLOAD for x-amz-content-sha256

    Returns:
        dict: Signed headers
    """
    request = AWSRequest(method=method, url=url, data=body, headers=headers)
    SigV4Auth(credentials, service, region).add_auth(request)

    signed_headers = dict(request.headers)

    # For some operations (POST multipart/form-data), AWS S3 requires UNSIGNED-PAYLOAD
    if unsigned_payload:
        signed_headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"

    return signed_headers
