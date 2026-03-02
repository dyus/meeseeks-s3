"""SSE-C (Server-Side Encryption with Customer-Provided Keys) utilities."""

import base64
import hashlib


DEFAULT_SSE_C_KEY_BYTES = hashlib.sha256(b"reverse_s3_ssec_default_key").digest()


def generate_sse_c_key(key_bytes: bytes | None = None) -> tuple[str, str]:
    """Generate SSE-C key and MD5 in base64 format.

    Args:
        key_bytes: Raw key bytes (default: DEFAULT_SSE_C_KEY_BYTES)

    Returns:
        Tuple of (key_base64, key_md5_base64)
    """
    if key_bytes is None:
        key_bytes = DEFAULT_SSE_C_KEY_BYTES
    key_b64 = base64.b64encode(key_bytes).decode("utf-8")
    key_md5 = base64.b64encode(hashlib.md5(key_bytes).digest()).decode("utf-8")
    return key_b64, key_md5
