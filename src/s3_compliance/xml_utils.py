"""XML parsing utilities for S3 responses."""

import re


def extract_error_info(response_text: str) -> tuple[str | None, str | None]:
    """Extract error code and message from S3 XML error response.

    Returns:
        Tuple of (error_code, error_message), either may be None.
    """
    code_match = re.search(r"<Code>([^<]+)</Code>", response_text)
    msg_match = re.search(r"<Message>([^<]+)</Message>", response_text)
    return (
        code_match.group(1) if code_match else None,
        msg_match.group(1) if msg_match else None,
    )


def extract_upload_id(response_text: str) -> str | None:
    """Extract UploadId from CreateMultipartUpload XML response."""
    match = re.search(r"<UploadId>([^<]+)</UploadId>", response_text)
    return match.group(1) if match else None
