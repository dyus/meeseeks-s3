"""Range request tests for SSE-C multipart upload objects.

Happy-path tests verifying byte-range reads on a 2-part SSE-C encrypted
multipart object (Part 1 = 5 MB of 'A', Part 2 = 1 KB of 'B').

These tests are independent from AWS — intended to run with --endpoint=custom.
"""

import uuid

import pytest

from s3_compliance.client import S3ClientFactory
from s3_compliance.sse_c import generate_sse_c_key


PART1_SIZE = 5 * 1024 * 1024  # 5 MB
PART2_SIZE = 1024  # 1 KB
TOTAL_SIZE = PART1_SIZE + PART2_SIZE  # 5,243,904 bytes

PART1_BODY = b"A" * PART1_SIZE
PART2_BODY = b"B" * PART2_SIZE
FULL_BODY = PART1_BODY + PART2_BODY


@pytest.mark.s3_handler("GetObject")
@pytest.mark.sse_c
class TestSSECMultipartRangeRequests:
    """Range requests on a 2-part SSE-C multipart object."""

    @pytest.fixture(scope="class")
    def test_key(self):
        return f"test-ssec-range-{uuid.uuid4().hex[:8]}"

    @pytest.fixture(scope="class")
    def ssec_key(self):
        key_b64, key_md5 = generate_sse_c_key()
        return {"key_b64": key_b64, "key_md5": key_md5}

    @pytest.fixture(scope="class")
    def completed_ssec_multipart(self, request, test_bucket, test_key, ssec_key, setup_test_bucket):
        """Create 2-part SSE-C multipart object on custom endpoint only."""
        endpoint_mode = request.config.getoption("--endpoint")

        ssec_params = {
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKey": ssec_key["key_b64"],
            "SSECustomerKeyMD5": ssec_key["key_md5"],
        }

        def _add_forwarded_proto(params, **kwargs):
            params["headers"]["X-Forwarded-Proto"] = "https"

        def _create_on_endpoint(client, register_proto=False):
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
                Bucket=test_bucket, Key=test_key, **ssec_params,
            )
            upload_id = mpu["UploadId"]

            part1 = client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=upload_id, PartNumber=1,
                Body=PART1_BODY, **ssec_params,
            )
            part2 = client.upload_part(
                Bucket=test_bucket, Key=test_key,
                UploadId=upload_id, PartNumber=2,
                Body=PART2_BODY, **ssec_params,
            )

            client.complete_multipart_upload(
                Bucket=test_bucket, Key=test_key,
                UploadId=upload_id,
                MultipartUpload={"Parts": [
                    {"PartNumber": 1, "ETag": part1["ETag"]},
                    {"PartNumber": 2, "ETag": part2["ETag"]},
                ]},
            )

            for event_name in events_to_clean:
                client.meta.events.unregister(event_name, _add_forwarded_proto)

            return client

        clients_to_cleanup = []

        if endpoint_mode == "custom":
            factory = S3ClientFactory()
            client = factory.create_client("custom")
            _create_on_endpoint(client, register_proto=True)
            clients_to_cleanup.append(client)

        elif endpoint_mode == "both":
            from s3_compliance.client import S3ClientFactory as Factory

            # AWS
            aws_factory = Factory()
            aws_client = aws_factory.create_client("aws")
            _create_on_endpoint(aws_client, register_proto=False)
            clients_to_cleanup.append(aws_client)

            # Custom
            custom_client = aws_factory.create_client("custom")
            _create_on_endpoint(custom_client, register_proto=True)
            clients_to_cleanup.append(custom_client)

        else:
            # aws-only
            factory = S3ClientFactory()
            client = factory.create_client("aws")
            _create_on_endpoint(client, register_proto=False)
            clients_to_cleanup.append(client)

        yield

        for client in clients_to_cleanup:
            try:
                client.delete_object(Bucket=test_bucket, Key=test_key)
            except Exception:
                pass

    def _ssec_headers(self, ssec_key):
        return {
            "x-amz-server-side-encryption-customer-algorithm": "AES256",
            "x-amz-server-side-encryption-customer-key": ssec_key["key_b64"],
            "x-amz-server-side-encryption-customer-key-MD5": ssec_key["key_md5"],
        }

    @pytest.mark.usefixtures("completed_ssec_multipart")
    def test_range_full_first_part(
        self, test_bucket, test_key, ssec_key, make_request, json_metadata,
    ):
        """Range request for the entire first part (5 MB of A)."""
        headers = {
            **self._ssec_headers(ssec_key),
            "Range": f"bytes=0-{PART1_SIZE - 1}",
        }

        response = make_request("GET", f"/{test_bucket}/{test_key}", headers=headers)

        json_metadata["range"] = f"bytes=0-{PART1_SIZE - 1}"
        json_metadata["expected_size"] = PART1_SIZE

        if hasattr(response, "comparison"):
            resp = response.custom
        else:
            resp = response

        assert resp.status_code == 206, f"Expected 206, got {resp.status_code}: {resp.text[:200]}"
        assert len(resp.content) == PART1_SIZE, f"Expected {PART1_SIZE} bytes, got {len(resp.content)}"
        assert resp.content == PART1_BODY

    @pytest.mark.usefixtures("completed_ssec_multipart")
    def test_range_middle_of_first_part(
        self, test_bucket, test_key, ssec_key, make_request, json_metadata,
    ):
        """Range request for a chunk in the middle of Part 1 (not from start, not to end)."""
        start, end = 1000, 2000
        expected_size = end - start + 1

        headers = {
            **self._ssec_headers(ssec_key),
            "Range": f"bytes={start}-{end}",
        }

        response = make_request("GET", f"/{test_bucket}/{test_key}", headers=headers)

        json_metadata["range"] = f"bytes={start}-{end}"
        json_metadata["expected_size"] = expected_size

        if hasattr(response, "comparison"):
            resp = response.custom
        else:
            resp = response

        assert resp.status_code == 206, f"Expected 206, got {resp.status_code}: {resp.text[:200]}"
        assert len(resp.content) == expected_size, f"Expected {expected_size} bytes, got {len(resp.content)}"
        assert resp.content == b"A" * expected_size

    @pytest.mark.usefixtures("completed_ssec_multipart")
    def test_range_across_part_boundary(
        self, test_bucket, test_key, ssec_key, make_request, json_metadata,
    ):
        """Range request spanning both parts (tail of Part 1 + all of Part 2)."""
        start = PART1_SIZE - 80  # 80 bytes before Part 1 ends
        end = TOTAL_SIZE - 1  # end of Part 2
        expected_body = b"A" * 80 + PART2_BODY
        expected_size = len(expected_body)

        headers = {
            **self._ssec_headers(ssec_key),
            "Range": f"bytes={start}-{end}",
        }

        response = make_request("GET", f"/{test_bucket}/{test_key}", headers=headers)

        json_metadata["range"] = f"bytes={start}-{end}"
        json_metadata["expected_size"] = expected_size

        if hasattr(response, "comparison"):
            resp = response.custom
        else:
            resp = response

        assert resp.status_code == 206, f"Expected 206, got {resp.status_code}: {resp.text[:200]}"
        assert len(resp.content) == expected_size, f"Expected {expected_size} bytes, got {len(resp.content)}"
        assert resp.content == expected_body

    @pytest.mark.usefixtures("completed_ssec_multipart")
    def test_range_full_second_part(
        self, test_bucket, test_key, ssec_key, make_request, json_metadata,
    ):
        """Range request for the entire second part (1 KB of B)."""
        start = PART1_SIZE
        end = TOTAL_SIZE - 1

        headers = {
            **self._ssec_headers(ssec_key),
            "Range": f"bytes={start}-{end}",
        }

        response = make_request("GET", f"/{test_bucket}/{test_key}", headers=headers)

        json_metadata["range"] = f"bytes={start}-{end}"
        json_metadata["expected_size"] = PART2_SIZE

        if hasattr(response, "comparison"):
            resp = response.custom
        else:
            resp = response

        assert resp.status_code == 206, f"Expected 206, got {resp.status_code}: {resp.text[:200]}"
        assert len(resp.content) == PART2_SIZE, f"Expected {PART2_SIZE} bytes, got {len(resp.content)}"
        assert resp.content == PART2_BODY

    @pytest.mark.usefixtures("completed_ssec_multipart")
    def test_range_suffix_last_bytes(
        self, test_bucket, test_key, ssec_key, make_request, json_metadata,
    ):
        """Suffix range request for the last 512 bytes (tail of Part 2)."""
        suffix_len = 512
        expected_body = b"B" * suffix_len

        headers = {
            **self._ssec_headers(ssec_key),
            "Range": f"bytes=-{suffix_len}",
        }

        response = make_request("GET", f"/{test_bucket}/{test_key}", headers=headers)

        json_metadata["range"] = f"bytes=-{suffix_len}"
        json_metadata["expected_size"] = suffix_len

        if hasattr(response, "comparison"):
            resp = response.custom
        else:
            resp = response

        assert resp.status_code == 206, f"Expected 206, got {resp.status_code}: {resp.text[:200]}"
        assert len(resp.content) == suffix_len, f"Expected {suffix_len} bytes, got {len(resp.content)}"
        assert resp.content == expected_body
