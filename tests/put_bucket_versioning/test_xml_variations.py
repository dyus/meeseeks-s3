"""Tests for PutBucketVersioning XML structure variations.

Verifies S3 behavior with various XML edge cases: missing elements,
missing namespace, no XML declaration, duplicate elements, extra elements,
and whitespace in Status value.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningXMLVariations:
    """Test PutBucketVersioning with various XML structure variations."""

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_versioning_configuration(
        self, test_bucket, make_request, json_metadata
    ):
        """<VersioningConfiguration></VersioningConfiguration> with no Status element."""
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            b"</VersioningConfiguration>"
        )
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_status_element(
        self, test_bucket, make_request, json_metadata
    ):
        """<Status></Status> with no text content."""
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            b"<Status></Status>"
            b"</VersioningConfiguration>"
        )
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_missing_xmlns_namespace(
        self, test_bucket, make_request, json_metadata
    ):
        """VersioningConfiguration without xmlns attribute."""
        body = build_versioning_xml("Enabled", xmlns=False)
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_no_xml_declaration(
        self, test_bucket, make_request, json_metadata
    ):
        """XML body without <?xml ...?> prolog."""
        body = (
            b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            b"<Status>Enabled</Status>"
            b"</VersioningConfiguration>"
        )
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_duplicate_status_elements(
        self, test_bucket, make_request, json_metadata
    ):
        """Two Status elements in one VersioningConfiguration."""
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            b"<Status>Enabled</Status>"
            b"<Status>Suspended</Status>"
            b"</VersioningConfiguration>"
        )
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_unknown_extra_element(
        self, test_bucket, make_request, json_metadata
    ):
        """Unknown element alongside Status."""
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            b"<Status>Enabled</Status>"
            b"<Foo>bar</Foo>"
            b"</VersioningConfiguration>"
        )
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_status_with_leading_trailing_whitespace(
        self, test_bucket, make_request, json_metadata
    ):
        """Status value with whitespace: ' Enabled '."""
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            b"<Status> Enabled </Status>"
            b"</VersioningConfiguration>"
        )
        headers = {"Content-Type": "application/xml"}

        response = make_request(
            "PUT",
            f"/{test_bucket}",
            body=body,
            headers=headers,
            query_params="?versioning",
        )

        if hasattr(response, "comparison"):
            json_metadata["aws_status"] = response.aws.status_code
            json_metadata["custom_status"] = response.custom.status_code
            if response.aws.status_code >= 400:
                error_code, error_msg = extract_error_info(response.aws.text)
                json_metadata["aws_error_code"] = error_code
                json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            json_metadata["status"] = response.status_code
            if response.status_code >= 400:
                error_code, error_msg = extract_error_info(response.text)
                json_metadata["error_code"] = error_code
                json_metadata["error_message"] = error_msg
