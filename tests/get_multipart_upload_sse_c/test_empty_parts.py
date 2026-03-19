"""GetObject tests for SSE-C multipart uploads with zero-byte parts.

Tests verifying that GetObject works correctly on SSE-C multipart objects
where one or more parts have zero size.

These tests are independent from AWS — intended to run with --endpoint=custom.
"""

import uuid

import pytest

from s3_compliance.client import S3ClientFactory
from s3_compliance.sse_c import generate_sse_c_key


PART_5MB = b"A" * (5 * 1024 * 1024)


@pytest.mark.s3_handler("GetObject")
@pytest.mark.sse_c
class TestSSECMultipartEmptyParts:
    """GetObject on SSE-C multipart objects with zero-byte parts."""

    @pytest.fixture(scope="class")
    def ssec_key(self):
        key_b64, key_md5 = generate_sse_c_key()
        return {"key_b64": key_b64, "key_md5": key_md5}

    def _ssec_params(self, ssec_key):
        return {
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": ssec_key["key_b64"],
            "SSECustomerKeyMD5": ssec_key["key_md5"],
        }

    def _ssec_headers(self, ssec_key):
        return {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": ssec_key["key_b64"],
            "x-amz-server-side-encryption-customer-key-MD5": ssec_key["key_md5"],
        }

    def _create_mpu_on_endpoint(self, client, bucket, key, parts_bodies, ssec_params, register_proto=False):
        """Create multipart upload with given part bodies, complete it, return client for cleanup."""
        def _add_forwarded_proto(params, **kwargs):
            params["headers"]["X-Forwarded-Proto"] = "https"

        events_to_clean = []
        if register_proto:
            for event_name in [
                "before-call.s3.CreateMultipartUpload",
                "before-call.s3.UploadPart",
                "before-call.s3.CompleteMultipartUpload",
            ]:
                client.meta.events.register(event_name, _add_forwarded_proto)
                events_to_clean.append(event_name)

        mpu = client.create_multipart_upload(
            Bucket=bucket, Key=key, **ssec_params,
        )
        upload_id = mpu["UploadId"]

        parts = []
        for i, body in enumerate(parts_bodies, 1):
            resp = client.upload_part(
                Bucket=bucket, Key=key,
                UploadId=upload_id, PartNumber=i,
                Body=body, **ssec_params,
            )
            parts.append({"PartNumber": i, "ETag": resp["ETag"]})

        client.complete_multipart_upload(
            Bucket=bucket, Key=key,
            UploadId=upload_id,
            MultipartUpload={"Parts": parts},
        )

        for event_name in events_to_clean:
            client.meta.events.unregister(event_name, _add_forwarded_proto)

    def _create_fixture(self, request, test_bucket, test_key, ssec_key, parts_bodies):
        """Generic fixture: create MPU with given parts on active endpoint(s)."""
        endpoint_mode = request.config.getoption("--endpoint")
        ssec_params = self._ssec_params(ssec_key)
        clients_to_cleanup = []

        if endpoint_mode == "custom":
            factory = S3ClientFactory()
            client = factory.create_client("custom")
            self._create_mpu_on_endpoint(client, test_bucket, test_key, parts_bodies, ssec_params, register_proto=True)
            clients_to_cleanup.append(client)
        elif endpoint_mode == "both":
            factory = S3ClientFactory()
            aws_client = factory.create_client("aws")
            self._create_mpu_on_endpoint(aws_client, test_bucket, test_key, parts_bodies, ssec_params, register_proto=False)
            clients_to_cleanup.append(aws_client)
            custom_client = factory.create_client("custom")
            self._create_mpu_on_endpoint(custom_client, test_bucket, test_key, parts_bodies, ssec_params, register_proto=True)
            clients_to_cleanup.append(custom_client)
        else:
            factory = S3ClientFactory()
            client = factory.create_client("aws")
            self._create_mpu_on_endpoint(client, test_bucket, test_key, parts_bodies, ssec_params, register_proto=False)
            clients_to_cleanup.append(client)

        yield

        for client in clients_to_cleanup:
            try:
                client.delete_object(Bucket=test_bucket, Key=test_key)
            except Exception:
                pass

    # --- Test: single zero-byte part ---

    @pytest.fixture
    def key_single_empty(self):
        return f"test-ssec-mpu-empty-single-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def mpu_single_empty_part(self, request, test_bucket, key_single_empty, ssec_key, setup_test_bucket):
        """MPU with a single 0-byte part."""
        yield from self._create_fixture(request, test_bucket, key_single_empty, ssec_key, [b""])

    @pytest.mark.usefixtures("mpu_single_empty_part")
    def test_get_single_empty_part(
        self, test_bucket, key_single_empty, ssec_key, make_request, json_metadata,
    ):
        """GetObject on MPU with a single 0-byte part should return empty body."""
        headers = self._ssec_headers(ssec_key)

        response = make_request("GET", f"/{test_bucket}/{key_single_empty}", headers=headers)

        json_metadata["parts"] = "1 x 0B"

        if hasattr(response, "comparison"):
            resp = response.custom
        else:
            resp = response

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:200]}"
        assert resp.content == b"", f"Expected empty body, got {len(resp.content)} bytes"

    # --- Test: 5 MB + 0-byte last part ---

    @pytest.fixture
    def key_last_empty(self):
        return f"test-ssec-mpu-empty-last-{uuid.uuid4().hex[:8]}"

    @pytest.fixture
    def mpu_last_part_empty(self, request, test_bucket, key_last_empty, ssec_key, setup_test_bucket):
        """MPU with 5 MB first part and 0-byte last part."""
        yield from self._create_fixture(request, test_bucket, key_last_empty, ssec_key, [PART_5MB, b""])

    @pytest.mark.usefixtures("mpu_last_part_empty")
    def test_get_with_empty_last_part(
        self, test_bucket, key_last_empty, ssec_key, make_request, json_metadata,
    ):
        """GetObject on MPU with 5MB + 0B should return only the 5 MB content."""
        headers = self._ssec_headers(ssec_key)

        response = make_request("GET", f"/{test_bucket}/{key_last_empty}", headers=headers)

        json_metadata["parts"] = "5MB + 0B"

        if hasattr(response, "comparison"):
            resp = response.custom
        else:
            resp = response

        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:200]}"
        assert len(resp.content) == len(PART_5MB), f"Expected {len(PART_5MB)} bytes, got {len(resp.content)}"
        assert resp.content == PART_5MB

