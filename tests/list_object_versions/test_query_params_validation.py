"""Tests for ListObjectVersions query parameter validation order.

Determines and verifies the full validation pipeline via pair-wise tests.
Each pair sends two invalid parameters simultaneously — the first error
returned reveals which parameter is validated first.

Seven distinct error tiers (in validation order):

  1. max-keys (non-integer)        → "Provided max-keys not an integer or within integer range"
  2. dependency (vid without key)   → "A version-id marker cannot be specified without a key marker."
  3. empty version-id-marker ("")   → "A version-id marker cannot be empty."
  4. version-id-marker (bad format) → "Invalid version id specified"
  5. encoding-type (invalid value)  → "Invalid Encoding Method specified in Request"
  6. null byte in key-marker/prefix → "Value must be a sequence of Unicode characters and cannot include Null."
  7. null byte in delimiter         → 500 InternalError (AWS bug)

key-marker, prefix, delimiter never trigger errors for valid Unicode (only null byte).

Supports --endpoint=aws, --endpoint=custom, and --endpoint=both.
"""

import re
import xml.etree.ElementTree as ET

import pytest

from s3_compliance.xml_utils import extract_error_info

from .conftest import build_versions_query


NS = "http://s3.amazonaws.com/doc/2006-03-01/"


def _get_response(response):
    """Get the response object (handles both single and comparison modes)."""
    if hasattr(response, "comparison"):
        return response.aws
    return response


def _parse_field(text, tag):
    """Extract a single field from ListVersionsResult XML."""
    root = ET.fromstring(text)
    el = root.find(f"{{{NS}}}{tag}")
    return el.text if el is not None else None


# ---------------------------------------------------------------------------
# Helper to reduce boilerplate: assert 400 and check which error message won
# ---------------------------------------------------------------------------

def _assert_error_contains(response, json_metadata, expected_substr):
    """Assert 400 and that error message contains expected_substr (lowercase)."""
    if hasattr(response, "comparison"):
        assert response.aws.status_code == 400, (
            f"Expected 400, got {response.aws.status_code}: {response.aws.text[:200]}"
        )
        error_code, error_msg = extract_error_info(response.aws.text)
        json_metadata["aws_error_code"] = error_code
        json_metadata["aws_error_message"] = error_msg
        assert error_code == "InvalidArgument"
        assert expected_substr in (error_msg or "").lower(), (
            f"Expected '{expected_substr}' in error, got: {error_msg}"
        )
        assert response.comparison.is_compliant, response.diff_summary
    else:
        assert response.status_code == 400, (
            f"Expected 400, got {response.status_code}: {response.text[:200]}"
        )
        error_code, error_msg = extract_error_info(response.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        assert error_code == "InvalidArgument"
        assert expected_substr in (error_msg or "").lower(), (
            f"Expected '{expected_substr}' in error, got: {error_msg}"
        )


# Error message substrings for each validation type
MAX_KEYS_ERR = "max-keys"
EMPTY_VID_ERR = "cannot be empty"
DEPENDENCY_ERR = "without a key marker"
VERSION_ID_ERR = "invalid version id"
ENCODING_ERR = "encoding method"
NULL_BYTE_ERR = "cannot include null"


def _extract_error_regex(text):
    """Extract error Code and Message using regex (fallback for invalid XML).

    S3 returns &#0; (null char reference) in error responses when the input
    contained a null byte. Standard XML parsers reject this, so we fall back
    to regex extraction.
    """
    code_m = re.search(r"<Code>([^<]+)</Code>", text)
    msg_m = re.search(r"<Message>([^<]+)</Message>", text)
    return (
        code_m.group(1) if code_m else None,
        msg_m.group(1) if msg_m else None,
    )


def _assert_error_regex(response, json_metadata, expected_substr):
    """Like _assert_error_contains but uses regex XML extraction.

    Needed for null-byte tests where the response XML contains &#0; which
    breaks standard XML parsers.
    """
    resp = _get_response(response)
    assert resp.status_code == 400, (
        f"Expected 400, got {resp.status_code}: {resp.text[:200]}"
    )
    error_code, error_msg = _extract_error_regex(resp.text)
    json_metadata["error_code"] = error_code
    json_metadata["error_message"] = error_msg
    assert error_code == "InvalidArgument", f"Expected InvalidArgument, got {error_code}"
    assert expected_substr in (error_msg or "").lower(), (
        f"Expected '{expected_substr}' in error, got: {error_msg}"
    )
    if hasattr(response, "comparison"):
        assert response.comparison.is_compliant, response.diff_summary


# =========================================================================
# 1. max-keys vs everything else
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestValidationOrderMaxKeys:
    """max-keys (non-integer) is validated FIRST — before all other checks."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_max_keys_over_encoding_type(self, test_bucket, make_request, json_metadata):
        """max-keys beats encoding-type."""
        query = build_versions_query(max_keys="abc", encoding_type="invalid")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_max_keys_over_version_id(self, test_bucket, make_request, json_metadata):
        """max-keys beats version-id-marker format check."""
        query = build_versions_query(
            key_marker="k", version_id_marker="bad-vid", max_keys="abc",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_max_keys_over_dependency(self, test_bucket, make_request, json_metadata):
        """max-keys beats dependency check (vid without key-marker)."""
        query = build_versions_query(version_id_marker="bad-vid", max_keys="abc")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_max_keys_over_empty_vid(self, test_bucket, make_request, json_metadata):
        """max-keys beats empty version-id-marker check."""
        query = build_versions_query(
            key_marker="k", version_id_marker="", max_keys="abc",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_max_keys_over_empty_vid_no_key(self, test_bucket, make_request, json_metadata):
        """max-keys beats empty-vid even when key-marker is also absent."""
        query = build_versions_query(version_id_marker="", max_keys="abc")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_max_keys_over_empty_key_with_vid(self, test_bucket, make_request, json_metadata):
        """max-keys beats dependency when key-marker is empty string."""
        query = build_versions_query(
            key_marker="", version_id_marker="bad-vid", max_keys="abc",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)


# =========================================================================
# 2. empty version-id-marker ("") — position in pipeline
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestValidationOrderEmptyVersionId:
    """Empty version-id-marker ('') triggers 'cannot be empty' error.

    This is a DIFFERENT error from the dependency check ('without a key marker').
    Need to determine where 'cannot be empty' sits relative to other checks.
    """

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_vid_with_key_over_encoding(self, test_bucket, make_request, json_metadata):
        """key-marker=k + version-id-marker="" + encoding=invalid → who wins?"""
        query = build_versions_query(
            key_marker="k", version_id_marker="", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        # Record the winner — we expect "cannot be empty" to beat encoding
        _assert_error_contains(response, json_metadata, EMPTY_VID_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_vid_no_key_over_encoding(self, test_bucket, make_request, json_metadata):
        """No key-marker + version-id-marker="" + encoding=invalid → who wins?

        Two competing errors: "cannot be empty" vs "without a key marker" vs encoding.
        """
        query = build_versions_query(
            version_id_marker="", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        # Record what wins — need to see if "cannot be empty" or "without a key" wins
        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            _, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_message"] = error_msg
            json_metadata["winner"] = (
                "empty_vid" if "cannot be empty" in (error_msg or "").lower()
                else "dependency" if "without a key" in (error_msg or "").lower()
                else "encoding" if "encoding" in (error_msg or "").lower()
                else "unknown"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            _, error_msg = extract_error_info(response.text)
            json_metadata["error_message"] = error_msg
            json_metadata["winner"] = (
                "empty_vid" if "cannot be empty" in (error_msg or "").lower()
                else "dependency" if "without a key" in (error_msg or "").lower()
                else "encoding" if "encoding" in (error_msg or "").lower()
                else "unknown"
            )

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_vid_with_empty_key_over_encoding(self, test_bucket, make_request, json_metadata):
        """key-marker="" + version-id-marker="" + encoding=invalid → who wins?"""
        query = build_versions_query(
            key_marker="", version_id_marker="", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            _, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_message"] = error_msg
            json_metadata["winner"] = (
                "empty_vid" if "cannot be empty" in (error_msg or "").lower()
                else "dependency" if "without a key" in (error_msg or "").lower()
                else "encoding" if "encoding" in (error_msg or "").lower()
                else "unknown"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            _, error_msg = extract_error_info(response.text)
            json_metadata["error_message"] = error_msg
            json_metadata["winner"] = (
                "empty_vid" if "cannot be empty" in (error_msg or "").lower()
                else "dependency" if "without a key" in (error_msg or "").lower()
                else "encoding" if "encoding" in (error_msg or "").lower()
                else "unknown"
            )

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_vid_standalone_with_key(self, test_bucket, make_request, json_metadata):
        """key-marker=k + version-id-marker="" (no other errors) → 'cannot be empty'."""
        query = build_versions_query(key_marker="k", version_id_marker="")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, EMPTY_VID_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_vid_standalone_no_key(self, test_bucket, make_request, json_metadata):
        """No key-marker + version-id-marker="" → is it 'empty' or 'without key'?"""
        query = build_versions_query(version_id_marker="")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            _, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_message"] = error_msg
            json_metadata["winner"] = (
                "empty_vid" if "cannot be empty" in (error_msg or "").lower()
                else "dependency" if "without a key" in (error_msg or "").lower()
                else "unknown"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            _, error_msg = extract_error_info(response.text)
            json_metadata["error_message"] = error_msg
            json_metadata["winner"] = (
                "empty_vid" if "cannot be empty" in (error_msg or "").lower()
                else "dependency" if "without a key" in (error_msg or "").lower()
                else "unknown"
            )


# =========================================================================
# 3. dependency check (vid without key-marker) vs other errors
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestValidationOrderDependency:
    """Dependency check: vid present + key-marker absent → 'without a key marker'.

    Sits AFTER max-keys, BEFORE encoding-type.
    """

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dependency_over_encoding(self, test_bucket, make_request, json_metadata):
        """vid without key + invalid encoding → dependency wins."""
        query = build_versions_query(
            version_id_marker="bad-vid", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, DEPENDENCY_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dependency_standalone(self, test_bucket, make_request, json_metadata):
        """vid without key-marker → 'without a key marker'."""
        query = build_versions_query(version_id_marker="bad-vid")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, DEPENDENCY_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dependency_empty_key_over_encoding(self, test_bucket, make_request, json_metadata):
        """key-marker="" + vid + invalid encoding → dependency wins over encoding."""
        query = build_versions_query(
            key_marker="", version_id_marker="bad-vid", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        # Empty key-marker is treated as absent for dependency check
        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            _, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_message"] = error_msg
            json_metadata["winner"] = (
                "dependency" if "without a key" in (error_msg or "").lower()
                else "encoding" if "encoding" in (error_msg or "").lower()
                else "unknown"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            _, error_msg = extract_error_info(response.text)
            json_metadata["error_message"] = error_msg
            json_metadata["winner"] = (
                "dependency" if "without a key" in (error_msg or "").lower()
                else "encoding" if "encoding" in (error_msg or "").lower()
                else "unknown"
            )

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dependency_empty_key_standalone(self, test_bucket, make_request, json_metadata):
        """key-marker="" + vid (no other errors) → dependency error."""
        query = build_versions_query(key_marker="", version_id_marker="bad-vid")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            _, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_message"] = error_msg
            # Could be "without a key" or "invalid version id" — depends on
            # whether empty key-marker is treated as absent
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            _, error_msg = extract_error_info(response.text)
            json_metadata["error_message"] = error_msg

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_dependency_empty_key_with_valid_vid(self, test_bucket, make_request, json_metadata):
        """key-marker="" + valid-format vid → dependency error even with valid vid format."""
        query = build_versions_query(
            key_marker="", version_id_marker="AElpAYzjYSpcGmodYgYGhF52bExgL7_v",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            _, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_message"] = error_msg
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            _, error_msg = extract_error_info(response.text)
            json_metadata["error_message"] = error_msg


# =========================================================================
# 4. version-id-marker format check vs encoding-type
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestValidationOrderVersionIdFormat:
    """version-id-marker format check (with key-marker present) vs encoding-type."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_version_id_over_encoding(self, test_bucket, make_request, json_metadata):
        """key=k + bad vid + invalid encoding → version-id wins."""
        query = build_versions_query(
            key_marker="k", version_id_marker="bad-vid", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, VERSION_ID_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_version_id_standalone(self, test_bucket, make_request, json_metadata):
        """key=k + bad vid → 'Invalid version id specified'."""
        query = build_versions_query(key_marker="k", version_id_marker="bad-vid")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, VERSION_ID_ERR)


# =========================================================================
# 5. encoding-type validation
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestValidationOrderEncodingType:
    """encoding-type is validated LAST among error-producing params."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_encoding_standalone(self, test_bucket, make_request, json_metadata):
        """encoding-type=invalid alone → 'Invalid Encoding Method'."""
        query = build_versions_query(encoding_type="invalid")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, ENCODING_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_encoding_valid_url(self, test_bucket, make_request, json_metadata):
        """encoding-type=url → 200."""
        query = build_versions_query(encoding_type="url")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 200


# =========================================================================
# 6. Triple and quadruple combinations
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestValidationOrderCombinations:
    """Multi-error combinations to confirm full pipeline order."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_all_invalid_max_keys_wins(self, test_bucket, make_request, json_metadata):
        """max-keys + vid + encoding all invalid → max-keys wins."""
        query = build_versions_query(
            key_marker="k", version_id_marker="bad-vid",
            max_keys="abc", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_vid_encoding_all_invalid_vid_wins(self, test_bucket, make_request, json_metadata):
        """key=k + bad vid + invalid encoding → version-id wins."""
        query = build_versions_query(
            key_marker="k", version_id_marker="bad-vid", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, VERSION_ID_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_no_key_vid_encoding_dependency_wins(self, test_bucket, make_request, json_metadata):
        """No key + bad vid + invalid encoding → dependency wins."""
        query = build_versions_query(
            version_id_marker="bad-vid", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, DEPENDENCY_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_no_key_all_invalid_max_keys_wins(self, test_bucket, make_request, json_metadata):
        """No key + bad vid + invalid max-keys + invalid encoding → max-keys wins."""
        query = build_versions_query(
            version_id_marker="bad-vid", max_keys="abc", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_key_empty_vid_max_keys_invalid(self, test_bucket, make_request, json_metadata):
        """key="" + vid="" + max-keys=abc → max-keys wins."""
        query = build_versions_query(
            key_marker="", version_id_marker="", max_keys="abc",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_empty_key_bad_vid_encoding_invalid(self, test_bucket, make_request, json_metadata):
        """key="" + bad vid + invalid encoding → who wins? (dependency or vid or encoding)."""
        query = build_versions_query(
            key_marker="", version_id_marker="bad-vid", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        if hasattr(response, "comparison"):
            assert response.aws.status_code == 400
            _, error_msg = extract_error_info(response.aws.text)
            json_metadata["aws_error_message"] = error_msg
            json_metadata["winner"] = (
                "dependency" if "without a key" in (error_msg or "").lower()
                else "version_id" if "invalid version id" in (error_msg or "").lower()
                else "encoding" if "encoding" in (error_msg or "").lower()
                else "unknown"
            )
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 400
            _, error_msg = extract_error_info(response.text)
            json_metadata["error_message"] = error_msg
            json_metadata["winner"] = (
                "dependency" if "without a key" in (error_msg or "").lower()
                else "version_id" if "invalid version id" in (error_msg or "").lower()
                else "encoding" if "encoding" in (error_msg or "").lower()
                else "unknown"
            )


# =========================================================================
# 7. max-keys and encoding-type individual validation
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestMaxKeysValidation:
    """max-keys parameter validation details."""

    @pytest.mark.usefixtures("setup_test_bucket")
    @pytest.mark.parametrize(
        "max_keys_value",
        [
            pytest.param("invalid-max-keys", id="non-numeric-string"),
            pytest.param("abc", id="alpha-string"),
            pytest.param("-1", id="negative"),
            pytest.param("1.5", id="float"),
            pytest.param("2147483648", id="int32-overflow"),
        ],
    )
    def test_invalid_max_keys_returns_400(
        self, test_bucket, make_request, json_metadata, max_keys_value,
    ):
        """Non-integer max-keys values → 400 InvalidArgument."""
        query = build_versions_query(max_keys=max_keys_value)
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    @pytest.mark.parametrize(
        "max_keys_value",
        [
            pytest.param("0", id="zero"),
            pytest.param("1", id="one"),
            pytest.param("999", id="under-default"),
            pytest.param("1000", id="default"),
            pytest.param("2147483647", id="int32-max"),
        ],
    )
    def test_valid_max_keys_returns_200(
        self, test_bucket, make_request, json_metadata, max_keys_value,
    ):
        """Valid integer max-keys → 200."""
        query = build_versions_query(max_keys=max_keys_value)
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        if hasattr(response, "comparison"):
            assert response.aws.status_code == 200
            assert response.comparison.is_compliant, response.diff_summary
        else:
            assert response.status_code == 200


# =========================================================================
# 8. Unicode in key-marker, version-id-marker, prefix — standalone behavior
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestUnicodeParamsStandalone:
    """Test how S3 handles single Unicode characters in query parameters.

    Empirical AWS results (2026-03-25):
      - key-marker: accepts Unicode (200), echoes percent-decoded bytes in XML
      - prefix: accepts Unicode (200), echoes percent-decoded bytes in XML
      - version-id-marker: rejects Unicode (400 "Invalid version id specified")
    """

    @pytest.mark.usefixtures("setup_test_bucket")
    @pytest.mark.parametrize(
        "unicode_char",
        [
            pytest.param("\u4e2d", id="cjk-middle"),      # 中
            pytest.param("\U0001f511", id="emoji-key"),    # 🔑
            pytest.param("\u00e9", id="latin-accent"),     # é
        ],
    )
    def test_unicode_key_marker_accepted(
        self, test_bucket, make_request, json_metadata, unicode_char,
    ):
        """key-marker with single Unicode character → 200 (accepts any string)."""
        query = build_versions_query(key_marker=unicode_char, max_keys="1")
        response = make_request("GET", f"/{test_bucket}", query_params=query)

        resp = _get_response(response)
        json_metadata["unicode_char"] = repr(unicode_char)
        assert resp.status_code == 200, (
            f"Expected 200 for Unicode key-marker, got {resp.status_code}: {resp.text[:200]}"
        )
        json_metadata["key_marker_echo"] = _parse_field(resp.text, "KeyMarker")

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    @pytest.mark.usefixtures("setup_test_bucket")
    @pytest.mark.parametrize(
        "unicode_char",
        [
            pytest.param("\u4e2d", id="cjk-middle"),
            pytest.param("\U0001f511", id="emoji-key"),
            pytest.param("\u00e9", id="latin-accent"),
        ],
    )
    def test_unicode_prefix_accepted(
        self, test_bucket, make_request, json_metadata, unicode_char,
    ):
        """prefix with single Unicode character → 200 (accepts any string)."""
        query = build_versions_query(prefix=unicode_char, max_keys="1")
        response = make_request("GET", f"/{test_bucket}", query_params=query)

        resp = _get_response(response)
        json_metadata["unicode_char"] = repr(unicode_char)
        assert resp.status_code == 200, (
            f"Expected 200 for Unicode prefix, got {resp.status_code}: {resp.text[:200]}"
        )
        json_metadata["prefix_echo"] = _parse_field(resp.text, "Prefix")

        if hasattr(response, "comparison"):
            assert response.comparison.is_compliant, response.diff_summary

    @pytest.mark.usefixtures("setup_test_bucket")
    @pytest.mark.parametrize(
        "unicode_char",
        [
            pytest.param("\u4e2d", id="cjk-middle"),
            pytest.param("\U0001f511", id="emoji-key"),
            pytest.param("\u00e9", id="latin-accent"),
        ],
    )
    def test_unicode_version_id_marker_rejected(
        self, test_bucket, make_request, json_metadata, unicode_char,
    ):
        """version-id-marker with single Unicode char + key-marker → 400 'Invalid version id'."""
        query = build_versions_query(
            key_marker="some-key", version_id_marker=unicode_char, max_keys="1",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        json_metadata["unicode_char"] = repr(unicode_char)
        _assert_error_contains(response, json_metadata, VERSION_ID_ERR)


# =========================================================================
# 9. Unicode params — validation order against other errors
#
# Empirical AWS results (2026-03-25):
#   - Unicode in key-marker/prefix does NOT cause errors (always valid)
#   - Unicode in version-id-marker triggers "Invalid version id" (same tier as ASCII bad vid)
#   - Validation order with Unicode matches the established pipeline:
#     max-keys > dependency > vid-format(unicode) > encoding-type
#   - key-marker/prefix with Unicode are transparent — encoding-type is the only
#     error when paired with invalid encoding
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestUnicodeValidationOrder:
    """Verify Unicode params follow the same validation pipeline as ASCII.

    Established order:
      1. max-keys  2. dependency  3. empty-vid  4. vid-format  5. encoding-type

    Unicode version-id-marker sits at tier 4 (vid-format).
    Unicode key-marker/prefix are always valid (no error tier).
    """

    # ----- P8: Unicode vid + invalid max-keys → max-keys wins (1 > 4) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_unicode_vid_vs_invalid_max_keys(
        self, test_bucket, make_request, json_metadata,
    ):
        """P8: key=k + vid=🔑 + max-keys=abc → max-keys wins (1 > 4)."""
        query = build_versions_query(
            key_marker="k", version_id_marker="\U0001f511", max_keys="abc",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    # ----- P9: Unicode vid + invalid encoding → vid-format wins (4 > 5) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_unicode_vid_vs_invalid_encoding(
        self, test_bucket, make_request, json_metadata,
    ):
        """P9: key=k + vid=中 + encoding=invalid → vid-format wins (4 > 5)."""
        query = build_versions_query(
            key_marker="k", version_id_marker="\u4e2d", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, VERSION_ID_ERR)

    # ----- P10: Unicode vid without key → dependency wins (2 > 4) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_unicode_vid_vs_dependency_no_key(
        self, test_bucket, make_request, json_metadata,
    ):
        """P10: vid=é without key-marker → dependency wins (2 > 4)."""
        query = build_versions_query(version_id_marker="\u00e9")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, DEPENDENCY_ERR)

    # ----- P11: Unicode key-marker + invalid encoding → encoding wins -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_unicode_key_marker_vs_invalid_encoding(
        self, test_bucket, make_request, json_metadata,
    ):
        """P11: key-marker=中 + encoding=invalid → encoding wins (key-marker is valid)."""
        query = build_versions_query(
            key_marker="\u4e2d", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, ENCODING_ERR)

    # ----- P12: Unicode prefix + invalid encoding → encoding wins -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_unicode_prefix_vs_invalid_encoding(
        self, test_bucket, make_request, json_metadata,
    ):
        """P12: prefix=🔑 + encoding=invalid → encoding wins (prefix is valid)."""
        query = build_versions_query(
            prefix="\U0001f511", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, ENCODING_ERR)

    # ----- P13: Unicode prefix + invalid max-keys → max-keys wins -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_unicode_prefix_vs_invalid_max_keys(
        self, test_bucket, make_request, json_metadata,
    ):
        """P13: prefix=é + max-keys=abc → max-keys wins (1 > valid prefix)."""
        query = build_versions_query(prefix="\u00e9", max_keys="abc")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    # ----- P14: Unicode key-marker + invalid max-keys → max-keys wins -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_unicode_key_marker_vs_invalid_max_keys(
        self, test_bucket, make_request, json_metadata,
    ):
        """P14: key-marker=🔑 + max-keys=abc → max-keys wins (1 > valid key-marker)."""
        query = build_versions_query(key_marker="\U0001f511", max_keys="abc")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    # ----- P15: Unicode key + Unicode vid + invalid encoding → vid-format wins (4 > 5) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_unicode_key_and_vid_vs_invalid_encoding(
        self, test_bucket, make_request, json_metadata,
    ):
        """P15: key=中 + vid=🔑 + encoding=invalid → vid-format wins (4 > 5)."""
        query = build_versions_query(
            key_marker="\u4e2d", version_id_marker="\U0001f511",
            encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, VERSION_ID_ERR)

    # ----- P16: All Unicode + invalid max-keys → max-keys wins -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_all_unicode_vs_invalid_max_keys(
        self, test_bucket, make_request, json_metadata,
    ):
        """P16: key=中 + vid=🔑 + prefix=é + max-keys=abc → max-keys wins (1 > all)."""
        query = build_versions_query(
            key_marker="\u4e2d", version_id_marker="\U0001f511",
            prefix="\u00e9", max_keys="abc",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    # ----- P17: Unicode vid without key + encoding → dependency wins (2 > 4,5) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_unicode_vid_no_key_vs_invalid_encoding(
        self, test_bucket, make_request, json_metadata,
    ):
        """P17: vid=🔑 without key + encoding=invalid → dependency wins (2 > 4,5)."""
        query = build_versions_query(
            version_id_marker="\U0001f511", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, DEPENDENCY_ERR)

    # ----- P18: Unicode vid without key + invalid max-keys → max-keys wins (1 > 2) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_unicode_vid_no_key_vs_invalid_max_keys(
        self, test_bucket, make_request, json_metadata,
    ):
        """P18: vid=中 without key + max-keys=abc → max-keys wins (1 > 2)."""
        query = build_versions_query(
            version_id_marker="\u4e2d", max_keys="abc",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)


# =========================================================================
# 10. Null byte (\x00) in parameters — standalone behavior
#
# Empirical AWS results (2026-03-25):
#   - key-marker=\x00  → 400 "Value must be a sequence of Unicode characters
#                              and cannot include Null."
#   - prefix=\x00      → 400 (same message)
#   - delimiter=\x00   → 500 InternalError (AWS bug!)
#   - vid=\x00 + key   → 400 "Invalid version id specified" (tier 4)
#   - vid=\x00 no key  → 400 "A version-id marker cannot be specified
#                              without a key marker." (tier 2)
#
# Note: S3 error XML contains &#0; (null char reference) in ArgumentValue,
# which is invalid XML. Standard parsers reject it, so we use regex extraction.
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestNullByteParamsStandalone:
    """Test how S3 handles null byte (\\x00) in query parameters."""

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_byte_key_marker(
        self, test_bucket, make_request, json_metadata,
    ):
        """key-marker=\\x00 → 400 'cannot include Null'."""
        query = build_versions_query(key_marker="\x00", max_keys="1")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_regex(response, json_metadata, NULL_BYTE_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_byte_prefix(
        self, test_bucket, make_request, json_metadata,
    ):
        """prefix=\\x00 → 400 'cannot include Null'."""
        query = build_versions_query(prefix="\x00", max_keys="1")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_regex(response, json_metadata, NULL_BYTE_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    @pytest.mark.edge_case
    def test_null_byte_delimiter(
        self, test_bucket, make_request, json_metadata,
    ):
        """delimiter=\\x00 → 500 InternalError (AWS bug).

        S3 crashes with InternalError when delimiter contains a null byte.
        This is an AWS bug — other params return a proper 400 error.
        """
        query = build_versions_query(delimiter="\x00", max_keys="1")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        resp = _get_response(response)
        json_metadata["status_code"] = resp.status_code
        error_code, error_msg = _extract_error_regex(resp.text)
        json_metadata["error_code"] = error_code
        json_metadata["error_message"] = error_msg
        assert resp.status_code == 500, (
            f"Expected 500 InternalError for delimiter=\\x00, got {resp.status_code}"
        )
        assert error_code == "InternalError"

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_byte_version_id_marker_with_key(
        self, test_bucket, make_request, json_metadata,
    ):
        """vid=\\x00 + key=k → 400 'Invalid version id' (tier 4, not null-check)."""
        query = build_versions_query(
            key_marker="k", version_id_marker="\x00", max_keys="1",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_regex(response, json_metadata, VERSION_ID_ERR)

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_byte_version_id_marker_without_key(
        self, test_bucket, make_request, json_metadata,
    ):
        """vid=\\x00 without key → 400 'without a key marker' (tier 2)."""
        query = build_versions_query(version_id_marker="\x00")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_regex(response, json_metadata, DEPENDENCY_ERR)


# =========================================================================
# 11. Null byte — validation order against other errors
#
# Established pipeline (tiers 1–7):
#   1. max-keys  2. dependency  3. empty-vid  4. vid-format
#   5. encoding-type  6. null-check (key/prefix)  7. delimiter-null (500)
#
# Key findings:
#   - Null-check for key-marker/prefix is tier 6 (AFTER encoding-type!)
#   - Null in vid is caught at tier 4 (vid-format) — no separate null-check
#   - Null in delimiter → 500, but only if no earlier tier fires
# =========================================================================

@pytest.mark.list_object_versions
@pytest.mark.s3_handler("ListObjectVersions")
class TestNullByteValidationOrder:
    """Verify where null byte errors sit in the validation pipeline."""

    # ----- NUL1: key=\x00 + max-keys=abc → max-keys wins (1 > 6) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_key_vs_invalid_max_keys(
        self, test_bucket, make_request, json_metadata,
    ):
        """NUL1: key=\\x00 + max-keys=abc → max-keys wins (1 > 6)."""
        query = build_versions_query(key_marker="\x00", max_keys="abc")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    # ----- NUL2: prefix=\x00 + max-keys=abc → max-keys wins (1 > 6) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_prefix_vs_invalid_max_keys(
        self, test_bucket, make_request, json_metadata,
    ):
        """NUL2: prefix=\\x00 + max-keys=abc → max-keys wins (1 > 6)."""
        query = build_versions_query(prefix="\x00", max_keys="abc")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    # ----- NUL3: key=\x00 + encoding=invalid → encoding wins (5 > 6) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_key_vs_invalid_encoding(
        self, test_bucket, make_request, json_metadata,
    ):
        """NUL3: key=\\x00 + encoding=invalid → encoding wins (5 > 6)."""
        query = build_versions_query(key_marker="\x00", encoding_type="invalid")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, ENCODING_ERR)

    # ----- NUL4: prefix=\x00 + encoding=invalid → encoding wins (5 > 6) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_prefix_vs_invalid_encoding(
        self, test_bucket, make_request, json_metadata,
    ):
        """NUL4: prefix=\\x00 + encoding=invalid → encoding wins (5 > 6)."""
        query = build_versions_query(prefix="\x00", encoding_type="invalid")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, ENCODING_ERR)

    # ----- NUL5: delimiter=\x00 + max-keys=abc → max-keys wins (1 > 7) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_delimiter_vs_invalid_max_keys(
        self, test_bucket, make_request, json_metadata,
    ):
        """NUL5: delimiter=\\x00 + max-keys=abc → max-keys wins (1 > 7)."""
        query = build_versions_query(delimiter="\x00", max_keys="abc")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    # ----- NUL6: delimiter=\x00 + encoding=invalid → encoding wins (5 > 7) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_delimiter_vs_invalid_encoding(
        self, test_bucket, make_request, json_metadata,
    ):
        """NUL6: delimiter=\\x00 + encoding=invalid → encoding wins (5 > 7)."""
        query = build_versions_query(delimiter="\x00", encoding_type="invalid")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, ENCODING_ERR)

    # ----- NUL7: vid=\x00 + key + max-keys=abc → max-keys wins (1 > 4) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_vid_with_key_vs_invalid_max_keys(
        self, test_bucket, make_request, json_metadata,
    ):
        """NUL7: vid=\\x00 + key=k + max-keys=abc → max-keys wins (1 > 4)."""
        query = build_versions_query(
            key_marker="k", version_id_marker="\x00", max_keys="abc",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)

    # ----- NUL8: vid=\x00 + key + encoding=invalid → vid-format wins (4 > 5) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_vid_with_key_vs_invalid_encoding(
        self, test_bucket, make_request, json_metadata,
    ):
        """NUL8: vid=\\x00 + key=k + encoding=invalid → vid-format wins (4 > 5)."""
        query = build_versions_query(
            key_marker="k", version_id_marker="\x00", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_regex(response, json_metadata, VERSION_ID_ERR)

    # ----- NUL9: vid=\x00 no key + encoding=invalid → dependency wins (2 > 4,5) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_vid_no_key_vs_invalid_encoding(
        self, test_bucket, make_request, json_metadata,
    ):
        """NUL9: vid=\\x00 no key + encoding=invalid → dependency wins (2 > 4,5)."""
        query = build_versions_query(
            version_id_marker="\x00", encoding_type="invalid",
        )
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_regex(response, json_metadata, DEPENDENCY_ERR)

    # ----- NUL10: vid=\x00 no key + max-keys=abc → max-keys wins (1 > 2) -----

    @pytest.mark.usefixtures("setup_test_bucket")
    def test_null_vid_no_key_vs_invalid_max_keys(
        self, test_bucket, make_request, json_metadata,
    ):
        """NUL10: vid=\\x00 no key + max-keys=abc → max-keys wins (1 > 2)."""
        query = build_versions_query(version_id_marker="\x00", max_keys="abc")
        response = make_request("GET", f"/{test_bucket}", query_params=query)
        _assert_error_contains(response, json_metadata, MAX_KEYS_ERR)
