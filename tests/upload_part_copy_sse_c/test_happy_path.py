"""Tests for UploadPartCopy with SSE-C happy paths.

UploadPartCopy has two groups of SSE-C headers (same as CopyObject):
- Destination (x-amz-server-side-encryption-customer-*): encrypt the part in MPU
- Source (x-amz-copy-source-server-side-encryption-customer-*): decrypt the source

Tests cover all 4 combinations:
1. Plain source -> SSE-C dest (dest headers only)
2. SSE-C source -> plain dest (source headers only)
3. SSE-C source -> SSE-C dest same key (both groups)
4. SSE-C source -> SSE-C dest new key (both groups, different keys)
"""

import hashlib

import pytest

from s3_compliance.sse_c import DEFAULT_SSE_C_KEY_BYTES, generate_sse_c_key


SECOND_KEY_BYTES = hashlib.sha256(b"reverse_s3_ssec_second_key").digest()


@pytest.mark.s3_handler("UploadPartCopy")
@pytest.mark.sse_c
class TestUploadPartCopySSECHappyPath:
    """Test UploadPartCopy with SSE-C for all source/dest encryption combinations."""

    def _make_upc_request(
        self, make_request, request, test_bucket, mpu, headers, part_number,
    ):
        """Make an UploadPartCopy request via make_request fixture."""
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            query_params = f"?uploadId={mpu['aws']}&partNumber={part_number}"
            custom_query_params = f"?uploadId={mpu['custom']}&partNumber={part_number}"
        else:
            query_params = f"?uploadId={mpu['upload_id']}&partNumber={part_number}"
            custom_query_params = None

        return make_request(
            "PUT",
            f"/{test_bucket}/{mpu['key']}",
            headers=headers,
            query_params=query_params,
            custom_query_params=custom_query_params,
        )

    # =========================================================================
    # Test 1: Plain source -> SSE-C destination
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_copy_plain_to_ssec(
        self, test_bucket, plain_source, ssec_multipart_upload,
        make_request, json_metadata, request,
    ):
        """Copy unencrypted source to SSE-C encrypted MPU part."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload,
            headers, part_number=1,
        )

        json_metadata["source_encryption"] = "none"
        json_metadata["dest_encryption"] = "SSE-C"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    # =========================================================================
    # Test 2: SSE-C source -> plain destination
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_copy_ssec_to_plain(
        self, test_bucket, ssec_source, plain_multipart_upload,
        make_request, json_metadata, request,
    ):
        """Copy SSE-C encrypted source to plain MPU part."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, plain_multipart_upload,
            headers, part_number=1,
        )

        json_metadata["source_encryption"] = "SSE-C"
        json_metadata["dest_encryption"] = "none"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    # =========================================================================
    # Test 3: SSE-C source -> SSE-C destination (same key)
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_copy_ssec_to_ssec_same_key(
        self, test_bucket, ssec_source, ssec_multipart_upload,
        make_request, json_metadata, request,
    ):
        """Copy SSE-C object to SSE-C MPU part using the same key."""
        key_b64, key_md5 = generate_sse_c_key()

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            # Source SSE-C headers (decrypt)
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": key_md5,
            # Dest SSE-C headers (encrypt) — same key
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload,
            headers, part_number=2,
        )

        json_metadata["source_encryption"] = "SSE-C"
        json_metadata["dest_encryption"] = "SSE-C"
        json_metadata["same_key"] = True

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    # =========================================================================
    # Test 4: SSE-C source -> SSE-C destination (different key)
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_copy_ssec_to_ssec_new_key(
        self, test_bucket, ssec_source, ssec_multipart_upload_alt,
        make_request, json_metadata, request,
    ):
        """Copy SSE-C object to SSE-C MPU part using a different key.

        Source encrypted with DEFAULT key (A), MPU created with SECOND key (B).
        Pass key A for source decryption, key B for dest encryption.
        """
        src_key_b64, src_key_md5 = generate_sse_c_key()
        dst_key_b64, dst_key_md5 = generate_sse_c_key(SECOND_KEY_BYTES)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{ssec_source}",
            # Source SSE-C headers (decrypt with key A)
            "x-amz-copy-source-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-copy-source-server-side-encryption-customer-key": src_key_b64,
            "x-amz-copy-source-server-side-encryption-customer-key-MD5": src_key_md5,
            # Dest SSE-C headers (encrypt with key B — matches MPU)
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": dst_key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": dst_key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload_alt,
            headers, part_number=1,
        )

        json_metadata["source_encryption"] = "SSE-C"
        json_metadata["dest_encryption"] = "SSE-C"
        json_metadata["same_key"] = False

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200, (
                f"AWS expected 200, got {response.aws.status_code}: {response.aws.text[:200]}"
            )
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 200, (
                f"Expected 200, got {response.status_code}: {response.text[:200]}"
            )
            json_metadata["status"] = response.status_code

    # =========================================================================
    # Test 5: Dest key mismatch with MPU key → rejected
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    @pytest.mark.edge_case
    def test_dest_key_mismatch_with_mpu_rejected(
        self, test_bucket, plain_source, ssec_multipart_upload,
        make_request, json_metadata, request,
    ):
        """UploadPartCopy rejects dest SSE-C key that doesn't match MPU key.

        MPU created with DEFAULT key (A), but we send SECOND key (B) as dest.
        AWS returns 400 InvalidRequest:
        "The provided encryption parameters did not match the ones used originally."
        """
        wrong_key_b64, wrong_key_md5 = generate_sse_c_key(SECOND_KEY_BYTES)

        headers = {
            "x-amz-copy-source": f"/{test_bucket}/{plain_source}",
            # Dest SSE-C headers — key B ≠ MPU key A
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": wrong_key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": wrong_key_md5,
        }

        response = self._make_upc_request(
            make_request, request, test_bucket, ssec_multipart_upload,
            headers, part_number=4,
        )

        json_metadata["mpu_key"] = "DEFAULT"
        json_metadata["dest_key"] = "SECOND (mismatch)"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
        else:
            assert response.status_code == 400
            json_metadata["status"] = response.status_code
