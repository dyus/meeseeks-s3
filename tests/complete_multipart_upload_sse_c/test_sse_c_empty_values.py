"""CompleteMultipartUpload SSE-C tests with empty string header values.

Tests whether AWS distinguishes between a missing SSE-C header
and a header present with an empty string value ("").

Mirrors tests/put_object_sse_c/test_sse_c_empty_values.py but for CompleteMultipartUpload.
"""

import uuid

import pytest

from s3_compliance.sse_c import generate_sse_c_key
from s3_compliance.xml_utils import extract_error_info

# Minimum part size for UploadPart (5 MB) — use smaller for tests, AWS allows small last part
PART_BODY = b"A" * 1024  # 1 KB — fine for single-part multipart upload


def build_complete_xml(parts: list[tuple[int, str]]) -> str:
    """Build CompleteMultipartUpload XML body.

    Args:
        parts: list of (part_number, etag) tuples.
    """
    parts_xml = "\n".join(
        f"    <Part>\n"
        f"        <PartNumber>{num}</PartNumber>\n"
        f"        <ETag>{etag}</ETag>\n"
        f"    </Part>"
        for num, etag in parts
    )
    return (
        "<CompleteMultipartUpload>\n"
        f"{parts_xml}\n"
        "</CompleteMultipartUpload>"
    )


@pytest.mark.s3_handler("CompleteMultipartUpload")
@pytest.mark.sse_c
@pytest.mark.edge_case
class TestSSECCompleteMultipartUploadEmptyValues:
    """Test CompleteMultipartUpload with empty string SSE-C header values.

    Compares behavior to missing headers (test_sse_c_headers.py)
    to determine if AWS treats empty vs absent differently.
    """

    @pytest.fixture
    def test_key(self):
        return f"test-ssec-empty-complete-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def ssec_multipart_with_part(self, request, s3_client, aws_client, test_bucket, test_key):
        """Create SSE-C multipart upload with one uploaded part.

        Returns dict with upload_id and etag (or dicts of them in both mode).
        Cleanup aborts the upload if not completed, or deletes the object if completed.
        """
        key_b64, key_md5 = generate_sse_c_key()
        endpoint_mode = request.config.getoption("--endpoint")

        ssec_params = {
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": key_b64,
            "SSECustomerKeyMD5": key_md5,
        }

        if endpoint_mode == "both":
            from s3_compliance.client import S3ClientFactory

            # AWS
            aws_mpu = aws_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            aws_upload_id = aws_mpu["UploadId"]
            aws_part = aws_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=aws_upload_id, PartNumber=1,
                Body=PART_BODY, **ssec_params,
            )
            aws_etag = aws_part["ETag"]

            # Custom
            factory = S3ClientFactory()
            custom_client = factory.create_client("custom")

            def _add_forwarded_proto(params, **kwargs):
                params["headers"]["X-Forwarded-Proto"] = "https"

            custom_client.meta.events.register("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)
            custom_mpu = custom_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            custom_client.meta.events.unregister("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)
            custom_upload_id = custom_mpu["UploadId"]
            custom_client.meta.events.register("before-call.s3.UploadPart", _add_forwarded_proto)
            custom_part = custom_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=custom_upload_id, PartNumber=1,
                Body=PART_BODY, **ssec_params,
            )
            custom_client.meta.events.unregister("before-call.s3.UploadPart", _add_forwarded_proto)
            custom_etag = custom_part["ETag"]

            yield {
                "aws": {"upload_id": aws_upload_id, "etag": aws_etag},
                "custom": {"upload_id": custom_upload_id, "etag": custom_etag},
            }

            for client, uid in [(aws_client, aws_upload_id), (custom_client, custom_upload_id)]:
                try:
                    client.abort_multipart_upload(
                        Bucket=test_bucket, Key=test_key, UploadId=uid,
                    )
                except Exception:
                    pass
                try:
                    client.delete_object(Bucket=test_bucket, Key=test_key)
                except Exception:
                    pass
        else:
            endpoint_is_custom = endpoint_mode == "custom"
            if endpoint_is_custom:
                def _add_forwarded_proto(params, **kwargs):
                    params["headers"]["X-Forwarded-Proto"] = "https"

                s3_client.meta.events.register("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)

            mpu = s3_client.create_multipart_upload(
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            upload_id = mpu["UploadId"]

            if endpoint_is_custom:
                s3_client.meta.events.unregister("before-call.s3.CreateMultipartUpload", _add_forwarded_proto)
                s3_client.meta.events.register("before-call.s3.UploadPart", _add_forwarded_proto)

            part = s3_client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=upload_id, PartNumber=1,
                Body=PART_BODY, **ssec_params,
            )
            etag = part["ETag"]

            if endpoint_is_custom:
                s3_client.meta.events.unregister("before-call.s3.UploadPart", _add_forwarded_proto)

            yield {"upload_id": upload_id, "etag": etag}

            try:
                s3_client.abort_multipart_upload(
                    Bucket=test_bucket, Key=test_key, UploadId=upload_id,
                )
            except Exception:
                pass
            try:
                s3_client.delete_object(Bucket=test_bucket, Key=test_key)
            except Exception:
                pass

    def _make_complete_request(
        self, make_request, request, test_bucket, test_key,
        multipart_data, xml_body, headers, custom_xml_body=None,
    ):
        """Make a CompleteMultipartUpload request via make_request fixture."""
        endpoint_mode = request.config.getoption("--endpoint")

        body = xml_body.encode("utf-8") if isinstance(xml_body, str) else xml_body
        custom_body = None
        custom_query_params = None

        if endpoint_mode == "both":
            query_params = f"?uploadId={multipart_data['aws']['upload_id']}"
            custom_query_params = f"?uploadId={multipart_data['custom']['upload_id']}"
            if custom_xml_body is not None:
                custom_body = custom_xml_body.encode("utf-8") if isinstance(custom_xml_body, str) else custom_xml_body
        else:
            query_params = f"?uploadId={multipart_data['upload_id']}"

        return make_request(
            "POST",
            f"/{test_bucket}/{test_key}",
            body=body,
            headers=headers,
            query_params=query_params,
            custom_body=custom_body,
            custom_query_params=custom_query_params,
        )

    # =========================================================================
    # Combo tests: one field empty, others valid
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_algorithm_with_valid_key_and_md5(
        self, test_bucket, test_key, ssec_multipart_with_part,
        make_request, request, json_metadata,
    ):
        """Empty algorithm + valid key + valid MD5.

        AWS treats empty string as an invalid algorithm value, not as absent.
        """
        key_b64, key_md5 = generate_sse_c_key()

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["empty_field"] = "algorithm"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
            assert error_code == "InvalidEncryptionAlgorithmError"
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidEncryptionAlgorithmError"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_key_with_valid_algorithm_and_md5(
        self, test_bucket, test_key, ssec_multipart_with_part,
        make_request, request, json_metadata,
    ):
        """Valid algorithm + empty key + valid MD5.

        AWS treats empty key as 0-byte key (too short).
        """
        _, key_md5 = generate_sse_c_key()

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": key_md5,
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["empty_field"] = "key"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
            assert error_code == "InvalidArgument"
            assert "too short" in error_msg
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "too short" in error_msg

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_md5_with_valid_algorithm_and_key(
        self, test_bucket, test_key, ssec_multipart_with_part,
        make_request, request, json_metadata,
    ):
        """Valid algorithm + valid key + empty MD5.

        AWS computes MD5 of the key and compares to empty string — mismatch.
        """
        key_b64, _ = generate_sse_c_key()

        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": key_b64,
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["empty_field"] = "md5"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
            assert error_code == "InvalidArgument"
            assert "MD5 hash" in error_msg
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "MD5 hash" in error_msg

    # =========================================================================
    # All three empty
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_all_three_headers_empty(
        self, test_bucket, test_key, ssec_multipart_with_part,
        make_request, request, json_metadata,
    ):
        """All three SSE-C headers present but empty.

        AWS validates key length first — empty key is "too short".
        """
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "",
            "x-amz-server-side-encryption-customer-key": "",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["empty_field"] = "all"

        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
            assert error_code == "InvalidArgument"
            assert "too short" in error_msg
        else:
            assert response.status_code == 400
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["status"] = response.status_code
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
            assert error_code == "InvalidArgument"
            assert "too short" in error_msg

    # =========================================================================
    # Single empty header only (others absent)
    # =========================================================================

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_algorithm_only(
        self, test_bucket, test_key, ssec_multipart_with_part,
        make_request, request, json_metadata,
    ):
        """Only algorithm header present but empty (key and MD5 absent).

        AWS detects SSE-C intent from any SSE-C header presence.
        """
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-algorithm": "",
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["empty_field"] = "algorithm_only"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_key_only(
        self, test_bucket, test_key, ssec_multipart_with_part,
        make_request, request, json_metadata,
    ):
        """Only key header present but empty (algorithm and MD5 absent).

        AWS detects SSE-C from key header, requires algorithm first.
        """
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-key": "",
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["empty_field"] = "key_only"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_sse_c_empty_md5_only(
        self, test_bucket, test_key, ssec_multipart_with_part,
        make_request, request, json_metadata,
    ):
        """Only MD5 header present but empty (algorithm and key absent).

        AWS detects SSE-C from MD5 header, requires algorithm first.
        """
        endpoint_mode = request.config.getoption("--endpoint")
        if endpoint_mode == "both":
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["aws"]["etag"])])
            custom_xml_body = build_complete_xml([(1, ssec_multipart_with_part["custom"]["etag"])])
        else:
            xml_body = build_complete_xml([(1, ssec_multipart_with_part["etag"])])
            custom_xml_body = None

        headers = {
            "Content-Type": "application/xml",
            "x-amz-server-side-encryption-customer-key-MD5": "",
        }

        response = self._make_complete_request(
            make_request, request, test_bucket, test_key,
            ssec_multipart_with_part, xml_body, headers, custom_xml_body,
        )

        json_metadata["empty_field"] = "md5_only"

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            error_code, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_code"] = error_code
            json_metadata["aws_error_message"] = error_msg
            json_metadata["custom_status"] = response.custom.status_code
        else:
            json_metadata["status"] = response.status_code
            error_code, error_msg = extract_error_info(response.text)
            json_metadata["error_code"] = error_code
            json_metadata["error_message"] = error_msg
