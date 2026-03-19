"""Golden file recording and replay for AWS S3 responses.

Records AWS responses as JSON files during --record-golden runs,
replays them in subsequent runs to avoid live AWS calls.

Golden file format (flat JSON array):
  - New format: each element has "request" + "response" keys
  - Old format: each element IS the response dict (status_code, headers, body)
  Both formats are supported for backward compatibility.
"""

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace


GOLDEN_DIR_NAME = "golden"

# Response headers scrubbed before saving (dynamic per-request)
SCRUB_HEADERS = {
    "x-amz-request-id",
    "x-amz-id-2",
    "date",
    "server",
}

# Request header values replaced with [REDACTED] (secrets)
REDACT_HEADER_VALUES = {
    "authorization",
    "x-amz-security-token",
    "x-amz-content-sha256",
}


def golden_file_path(test_nodeid: str) -> Path:
    """Convert pytest node ID to golden file path.

    Example:
        tests/put_object_sse_c/test_sse_c_headers.py::TestSSECPutObject::test_wrong_key
        → tests/put_object_sse_c/golden/TestSSECPutObject.test_wrong_key.json

        tests/put_object/test_put.py::TestPut::test_something[param1]
        → tests/put_object/golden/TestPut.test_something[param1].json
    """
    # Split node ID: "tests/module/test_file.py::Class::method[params]"
    file_part, *test_parts = test_nodeid.split("::")
    test_dir = Path(file_part).parent
    golden_dir = test_dir / GOLDEN_DIR_NAME

    # Build filename from class and method parts
    filename = ".".join(test_parts) + ".json"

    return golden_dir / filename


def scrub_response(resp_dict: dict) -> dict:
    """Remove dynamic headers before saving to golden file."""
    scrubbed_headers = {
        k: v for k, v in resp_dict.get("headers", {}).items()
        if k.lower() not in SCRUB_HEADERS
    }
    return {
        "status_code": resp_dict["status_code"],
        "headers": scrubbed_headers,
        "body": resp_dict["body"],
    }


def redact_request(request_info: dict) -> dict:
    """Redact sensitive values in request headers, keep all header names."""
    headers = {}
    for k, v in request_info.get("headers", {}).items():
        if k.lower() in REDACT_HEADER_VALUES:
            headers[k] = "[REDACTED]"
        else:
            headers[k] = v

    body = request_info.get("body", "")
    body_encoding = "utf-8"
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError:
            body = base64.b64encode(body).decode("ascii")
            body_encoding = "base64"
    elif body is None:
        body = ""

    result = {
        "method": request_info.get("method", ""),
        "path": request_info.get("path", ""),
        "query_params": request_info.get("query_params", ""),
        "headers": headers,
        "body": body,
    }
    if body_encoding != "utf-8":
        result["body_encoding"] = body_encoding
    return result


def save_golden(path: Path, responses: list[dict]):
    """Write responses to golden file (pretty-printed JSON)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(responses, indent=2, ensure_ascii=False) + "\n")


def load_golden(path: Path) -> list[dict]:
    """Load responses from golden file."""
    return json.loads(path.read_text())


@dataclass
class GoldenResponse:
    """Replays a recorded AWS response.

    Implements the same interface as requests.Response for the fields
    used by _response_to_dict(), ComparisonResponse, HTTPCapture,
    and test assertions.
    """

    status_code: int
    headers: dict
    text: str
    content: bytes

    # Request data from golden file (None for old-format files)
    _request_data: dict = None

    def __init__(self, data: dict, request_data: dict = None):
        self.status_code = data["status_code"]
        self.headers = data.get("headers", {})
        self.text = data.get("body", "")
        self.content = self.text.encode("utf-8")
        self._request_data = request_data

    @property
    def request(self):
        """Return a request-like object for HTTPCapture compatibility.

        For new-format golden files, returns a SimpleNamespace with
        method, url, headers, body — same interface as requests.Response.request.
        For old-format files, returns None.
        """
        if self._request_data is None:
            return None
        path = self._request_data.get("path", "")
        qp = self._request_data.get("query_params", "")
        return SimpleNamespace(
            method=self._request_data.get("method", ""),
            url=f"{path}{qp}",
            headers=self._request_data.get("headers", {}),
            body=self._request_data.get("body", ""),
        )


class GoldenRecorder:
    """Collects AWS responses during a recording run and saves on finalize.

    Each entry is stored as {"request": {...}, "response": {...}}.
    """

    def __init__(self, path: Path):
        self.path = path
        self.entries: list[dict] = []

    def record(self, resp_dict: dict, request_info: dict = None):
        """Add a scrubbed response (and optionally request) to the recording.

        Args:
            resp_dict: Response dict with status_code, headers, body.
            request_info: Optional dict with method, path, query_params, headers, body.
        """
        entry = {"response": scrub_response(resp_dict)}
        if request_info:
            entry["request"] = redact_request(request_info)
        self.entries.append(entry)

    def finalize(self):
        """Write collected entries to the golden file."""
        if self.entries:
            save_golden(self.path, self.entries)


class GoldenPlayer:
    """Replays responses from a golden file, one per make_request call."""

    def __init__(self, path: Path):
        self.entries = load_golden(path)
        self.index = 0

    def next(self) -> GoldenResponse:
        """Return next recorded response as GoldenResponse."""
        if self.index >= len(self.entries):
            raise IndexError(
                f"Golden file has {len(self.entries)} entries, "
                f"but test requested entry #{self.index + 1}. "
                f"Re-record with --record-golden."
            )
        entry = self.entries[self.index]
        self.index += 1
        return GoldenResponse(
            data=entry["response"],
            request_data=entry.get("request"),
        )


