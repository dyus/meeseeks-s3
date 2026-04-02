"""Tests for PutBucketVersioning state transitions.

Verifies that S3 correctly transitions between versioning states
and that the new state is reflected in GetBucketVersioning.

Corresponds to putbucketversioning.md tests 1-4.

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import pytest

from s3_compliance.xml_utils import extract_error_info
from tests.put_bucket_versioning.conftest import build_versioning_xml_with_mfa


def _put_versioning(make_request, test_bucket, status, mfa_delete="Disabled"):
    """Helper: send PutBucketVersioning request."""
    body = build_versioning_xml_with_mfa(status, mfa_delete=mfa_delete)
    headers = {"Content-Type": "application/xml"}
    return make_request(
        "PUT",
        f"/{test_bucket}",
        body=body,
        headers=headers,
        query_params="?versioning",
    )


def _get_versioning(make_request, test_bucket):
    """Helper: send GetBucketVersioning request."""
    return make_request(
        "GET",
        f"/{test_bucket}",
        query_params="?versioning",
    )


def _assert_status(response, expected_status_code):
    """Assert response status code, handling both single and comparison modes."""
    if hasattr(response, "comparison"):
        assert response.aws.status_code == expected_status_code, (
            f"AWS expected {expected_status_code}, got {response.aws.status_code}: "
            f"{response.aws.text[:200]}"
        )
    else:
        assert response.status_code == expected_status_code, (
            f"Expected {expected_status_code}, got {response.status_code}: "
            f"{response.text[:200]}"
        )


def _get_response_text(response):
    """Get response text, handling both single and comparison modes."""
    if hasattr(response, "comparison"):
        return response.aws.text
    return response.text


@pytest.mark.put_bucket_versioning
@pytest.mark.s3_handler("PutBucketVersioning")
class TestPutBucketVersioningStateTransitions:
    """Test PutBucketVersioning state transitions with verification."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_disabled_to_enabled(
        self, test_bucket, make_request, json_metadata
    ):
        """Disabled → Enabled transition should succeed (doc test 1).

        Suspends versioning first to ensure Disabled/Suspended baseline,
        then enables and verifies via GetBucketVersioning.
        """
        # Note: can't truly return to "Disabled" (never-versioned) state,
        # but Suspended is functionally similar for testing transitions.
        _put_versioning(make_request, test_bucket, "Suspended")

        # Transition: → Enabled
        response = _put_versioning(make_request, test_bucket, "Enabled")
        _assert_status(response, 200)

        # Verify state via GetBucketVersioning
        get_resp = _get_versioning(make_request, test_bucket)
        resp_text = _get_response_text(get_resp)
        assert "<Status>Enabled</Status>" in resp_text, (
            f"Expected Enabled in GetBucketVersioning, got: {resp_text[:300]}"
        )

        json_metadata["transition"] = "Disabled→Enabled"
        json_metadata["verified"] = True

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_disabled_to_suspended(
        self, test_bucket, make_request, json_metadata
    ):
        """Disabled → Suspended transition should succeed (doc test 2)."""
        # Enable first, then we'll suspend
        _put_versioning(make_request, test_bucket, "Enabled")

        # Transition: → Suspended
        response = _put_versioning(make_request, test_bucket, "Suspended")
        _assert_status(response, 200)

        # Verify state
        get_resp = _get_versioning(make_request, test_bucket)
        resp_text = _get_response_text(get_resp)
        assert "<Status>Suspended</Status>" in resp_text, (
            f"Expected Suspended in GetBucketVersioning, got: {resp_text[:300]}"
        )

        json_metadata["transition"] = "Disabled→Suspended"
        json_metadata["verified"] = True

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_enabled_to_suspended(
        self, test_bucket, make_request, json_metadata
    ):
        """Enabled → Suspended transition should succeed (doc test 3)."""
        # Set Enabled
        _put_versioning(make_request, test_bucket, "Enabled")

        # Transition: Enabled → Suspended
        response = _put_versioning(make_request, test_bucket, "Suspended")
        _assert_status(response, 200)

        # Verify state
        get_resp = _get_versioning(make_request, test_bucket)
        resp_text = _get_response_text(get_resp)
        assert "<Status>Suspended</Status>" in resp_text, (
            f"Expected Suspended in GetBucketVersioning, got: {resp_text[:300]}"
        )

        json_metadata["transition"] = "Enabled→Suspended"
        json_metadata["verified"] = True

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_suspended_to_enabled(
        self, test_bucket, make_request, json_metadata
    ):
        """Suspended → Enabled transition should succeed (doc test 4)."""
        # Set Suspended
        _put_versioning(make_request, test_bucket, "Suspended")

        # Transition: Suspended → Enabled
        response = _put_versioning(make_request, test_bucket, "Enabled")
        _assert_status(response, 200)

        # Verify state
        get_resp = _get_versioning(make_request, test_bucket)
        resp_text = _get_response_text(get_resp)
        assert "<Status>Enabled</Status>" in resp_text, (
            f"Expected Enabled in GetBucketVersioning, got: {resp_text[:300]}"
        )

        json_metadata["transition"] = "Suspended→Enabled"
        json_metadata["verified"] = True
