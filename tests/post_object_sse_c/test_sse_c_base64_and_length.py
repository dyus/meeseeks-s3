"""PostObject SSE-C tests for base64 encoding edge cases, key length boundaries, and MD5 edge cases.

Mirrors the edge case tests from put_object_sse_c/test_sse_c_headers.py
but adapted for PostObject's form-based upload.
"""

import base64
import hashlib
import os

import pytest

from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info
from tests.post_object_sse_c.conftest import ALL_SSEC_CONDITIONS, make_presigned_post


def _make_test(presigned, post_with_ssec, file_content, ssec_fields, json_metadata, s3_client, test_bucket, test_key):
    """Common helper: POST with SSE-C fields, record metadata, cleanup."""
    response = post_with_ssec(
        presigned["url"], presigned["fields"], file_content, ssec_fields,
    )

    json_metadata["status"] = response.status_code
    if response.status_code >= 400 and response.text:
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg

    try:
        s3_client.delete_object(Bucket=test_bucket, Key=test_key)
    except Exception:
        pass

    return response


@pytest.mark.post_object
@pytest.mark.s3_handler("PostObject")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestSSECPostObjectBase64EdgeCases:
    """Test PostObject with various base64 encoding edge cases for SSE-C key/MD5."""

    # =========================================================================
    # E. Base64 encoding edge cases
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_base64_with_spaces(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key base64 string with spaces inserted."""
        key_b64, key_md5 = generate_sse_c_key()
        spaced_key = " ".join(key_b64[i:i+4] for i in range(0, len(key_b64), 4))

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": spaced_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_base64_with_tabs_and_newlines(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key base64 string with tabs and newlines inserted."""
        key_b64, key_md5 = generate_sse_c_key()
        mid = len(key_b64) // 2
        mangled_key = key_b64[:mid] + "\t\n" + key_b64[mid:]

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": mangled_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_base64_without_padding(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key base64 with padding '=' stripped."""
        key_b64, key_md5 = generate_sse_c_key()
        no_pad_key = key_b64.rstrip("=")

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": no_pad_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_base64_with_extra_padding(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key base64 with extra padding '====' appended."""
        key_b64, key_md5 = generate_sse_c_key()
        extra_pad_key = key_b64 + "===="

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": extra_pad_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_url_safe_base64(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key encoded with URL-safe base64 (- and _ instead of + and /)."""
        key_bytes = os.urandom(32)
        url_safe_key = base64.urlsafe_b64encode(key_bytes).decode("utf-8")
        key_md5 = base64.b64encode(hashlib.md5(key_bytes).digest()).decode("utf-8")

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["key_value"] = url_safe_key

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": url_safe_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_and_md5_both_url_safe_base64(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Both key and MD5 encoded with URL-safe base64."""
        key_bytes = os.urandom(32)
        url_safe_key = base64.urlsafe_b64encode(key_bytes).decode("utf-8")
        url_safe_md5 = base64.urlsafe_b64encode(
            hashlib.md5(key_bytes).digest()
        ).decode("utf-8")

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["key_value"] = url_safe_key
        json_metadata["md5_value"] = url_safe_md5

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": url_safe_key,
            "x-amz-server-side-encryption-customer-key-MD5": url_safe_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_with_garbage_chars_in_base64(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key with non-base64 characters (!, @, #) mixed in."""
        key_b64, key_md5 = generate_sse_c_key()
        garbage_key = key_b64[:8] + "!@#$" + key_b64[8:]

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["key_value"] = garbage_key

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": garbage_key,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_valid_key_md5_without_padding(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Valid key, but MD5 has base64 padding stripped."""
        key_b64, key_md5 = generate_sse_c_key()
        no_pad_md5 = key_md5.rstrip("=")

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["md5_value"] = no_pad_md5
        json_metadata["original_md5"] = key_md5

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": no_pad_md5,
        }, json_metadata, s3_client, test_bucket, test_key)


@pytest.mark.post_object
@pytest.mark.s3_handler("PostObject")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestSSECPostObjectKeyLengthBoundary:
    """Test PostObject with various SSE-C key lengths and boundary values."""

    # =========================================================================
    # F. Key length boundary cases
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_customer_key_decodes_to_short_value(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key decodes to fewer than 32 bytes (16 bytes)."""
        short_key = b"\x01" * 16
        key_b64, key_md5 = generate_sse_c_key(short_key)

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["decoded_key_length"] = len(short_key)

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_customer_key_zz(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key = 'ZZ' (2-char base64, decodes to ~1 byte)."""
        key_md5 = base64.b64encode(hashlib.md5(base64.b64decode("ZZ==")).digest()).decode("utf-8")

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["key_value"] = "ZZ"

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "ZZ",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_customer_key_single_char_a(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key = 'a' (1 char, not valid base64 length)."""
        fake_md5 = base64.b64encode(hashlib.md5(b"a").digest()).decode("utf-8")

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["key_value"] = "a"

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "a",
            "x-amz-server-side-encryption-customer-key-MD5": fake_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_customer_key_latin1_chars(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key contains Latin-1 characters (non-ASCII but single-byte)."""
        latin1_key = "\xe9\xe8\xea" * 15  # 45 chars of latin1

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["key_value"] = repr(latin1_key)

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": latin1_key,
            "x-amz-server-side-encryption-customer-key-MD5": base64.b64encode(hashlib.md5(latin1_key.encode("latin-1")).digest()).decode("utf-8"),
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_customer_key(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key = '' (empty string)."""
        key_md5 = base64.b64encode(hashlib.md5(b"").digest()).decode("utf-8")

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["key_value"] = ""

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_customer_key_decodes_to_1_byte(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Key decodes to exactly 1 byte."""
        one_byte_key = b"\x42"
        key_b64, key_md5 = generate_sse_c_key(one_byte_key)

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["decoded_key_length"] = 1

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_short_key_zz_with_matching_md5(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """Short key 'ZZ' with correctly computed MD5 for that short key."""
        decoded = base64.b64decode("ZZ==")
        key_md5 = base64.b64encode(hashlib.md5(decoded).digest()).decode("utf-8")

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["key_value"] = "ZZ"
        json_metadata["md5_matches_key"] = True

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "ZZ",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_long_key_33_bytes_with_matching_md5(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """33-byte key with correctly computed MD5."""
        long_key = b"\xaa" * 33
        key_b64, key_md5 = generate_sse_c_key(long_key)

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["decoded_key_length"] = 33

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_31_bytes(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """31-byte key (one byte short of required 32)."""
        key_31 = b"\xbb" * 31
        key_b64, key_md5 = generate_sse_c_key(key_31)

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["decoded_key_length"] = 31

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_key_33_bytes(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """33-byte key (one byte over required 32)."""
        key_33 = b"\xcc" * 33
        key_b64, key_md5 = generate_sse_c_key(key_33)

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["decoded_key_length"] = 33

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }, json_metadata, s3_client, test_bucket, test_key)


@pytest.mark.post_object
@pytest.mark.s3_handler("PostObject")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestSSECPostObjectMD5EdgeCases:
    """Test PostObject with various SSE-C MD5 edge cases."""

    # =========================================================================
    # G. MD5 edge cases
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_md5_with_garbage_chars(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """MD5 value contains non-base64 characters."""
        key_b64, _ = generate_sse_c_key()
        garbage_md5 = "abc!@#def$%^ghi"

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["md5_value"] = garbage_md5

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": garbage_md5,
        }, json_metadata, s3_client, test_bucket, test_key)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_md5_decodes_to_wrong_length(
        self, s3_client, test_bucket, test_key, file_content, post_with_ssec, json_metadata,
    ):
        """MD5 is valid base64 but decodes to wrong length (not 16 bytes)."""
        key_b64, _ = generate_sse_c_key()
        wrong_len_md5 = base64.b64encode(b"\x00" * 8).decode("utf-8")  # 8 bytes, not 16

        presigned = make_presigned_post(s3_client, test_bucket, test_key, ssec_conditions=ALL_SSEC_CONDITIONS)
        json_metadata["md5_value"] = wrong_len_md5
        json_metadata["md5_decoded_length"] = 8

        _make_test(presigned, post_with_ssec, file_content, {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_len_md5,
        }, json_metadata, s3_client, test_bucket, test_key)
