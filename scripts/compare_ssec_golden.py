#!/usr/bin/env python3
"""Compare SSE-C golden file responses across all S3 operations.

Reads golden files from tests/*/golden/ directories, extracts status codes
and error info, and produces a cross-operation comparison table.

Usage:
    python scripts/compare_ssec_golden.py
    python scripts/compare_ssec_golden.py --markdown  # output as markdown
    python scripts/compare_ssec_golden.py --diff-only  # only show rows with differences
"""

import argparse
import json
import re
import sys
from pathlib import Path
from xml.etree import ElementTree


# Operations to compare (in display order)
OPERATIONS = [
    ("put_object_sse_c", "PutObject"),
    ("get_object_sse_c", "GetObject"),
    ("head_object_sse_c", "HeadObject"),
    ("create_multipart_upload_sse_c", "CreateMPU"),
    ("complete_multipart_upload_sse_c", "CompleteMPU"),
    ("upload_part_sse_c", "UploadPart"),
]

# Map from golden file test name to canonical test name
# Golden files are named: TestClassName.test_method_name.json
# We strip the class prefix to get a comparable test name
TEST_NAME_PATTERNS = {
    # GetObject/HeadObject prefixed tests -> canonical names
    r"test_get_ssec_object_": "test_sse_c_",
    r"test_head_ssec_object_": "test_sse_c_",
    r"test_get_ssec_": "test_sse_c_",
    r"test_head_ssec_": "test_sse_c_",
}


def normalize_test_name(golden_filename: str) -> str:
    """Extract and normalize test name from golden file name.

    Golden file: TestSSECPutObjectHeaders.test_sse_c_all_valid_headers_accepted.json
    Returns: test_sse_c_all_valid_headers_accepted
    """
    stem = golden_filename.replace(".json", "")
    # Split on first dot to separate class from method
    parts = stem.split(".", 1)
    if len(parts) == 2:
        test_name = parts[1]
    else:
        test_name = stem

    # Normalize operation-specific prefixes to canonical form
    for pattern, replacement in TEST_NAME_PATTERNS.items():
        test_name = re.sub(pattern, replacement, test_name)

    return test_name


def extract_error_from_xml(body: str) -> tuple[str | None, str | None]:
    """Extract error code and message from S3 XML error response."""
    if not body or not body.strip():
        return None, None
    try:
        root = ElementTree.fromstring(body)
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"
        code_el = root.find(f"{ns}Code")
        msg_el = root.find(f"{ns}Message")
        code = code_el.text if code_el is not None else None
        msg = msg_el.text if msg_el is not None else None
        return code, msg
    except ElementTree.ParseError:
        return None, None


def load_golden_responses(tests_dir: Path) -> dict[str, dict[str, dict]]:
    """Load all golden files and organize by normalized test name.

    Returns:
        {canonical_test_name: {operation_name: {"status": int, "error_code": str, "error_msg": str}}}
    """
    results: dict[str, dict[str, dict]] = {}

    for op_dir, op_label in OPERATIONS:
        golden_dir = tests_dir / op_dir / "golden"
        if not golden_dir.exists():
            continue

        for golden_file in sorted(golden_dir.glob("*.json")):
            test_name = normalize_test_name(golden_file.name)

            try:
                data = json.loads(golden_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue

            if not data:
                continue

            # Use first entry (most tests have single make_request call)
            entry = data[0]
            resp = entry.get("response", {})
            status = resp.get("status_code")
            body = resp.get("body", "")

            error_code, error_msg = extract_error_from_xml(body)

            # Build summary string
            if error_code:
                summary = f"{status} {error_code}"
            elif status and status < 400:
                summary = f"{status} OK"
            else:
                summary = str(status) if status else "?"

            if test_name not in results:
                results[test_name] = {}
            results[test_name][op_label] = {
                "status": status,
                "error_code": error_code,
                "error_msg": error_msg,
                "summary": summary,
            }

    return results


def find_differences(results: dict[str, dict[str, dict]]) -> dict[str, bool]:
    """For each test, check if all operations return the same status+error_code.

    Returns: {test_name: has_difference}
    """
    diffs = {}
    for test_name, ops in results.items():
        summaries = set()
        for op_data in ops.values():
            summaries.add((op_data["status"], op_data["error_code"]))
        diffs[test_name] = len(summaries) > 1
    return diffs


def print_table(results: dict, diffs: dict, diff_only: bool = False, markdown: bool = False):
    """Print comparison table."""
    op_labels = [label for _, label in OPERATIONS]

    # Filter tests
    test_names = sorted(results.keys())
    if diff_only:
        test_names = [t for t in test_names if diffs.get(t, False)]

    if not test_names:
        print("No differences found!" if diff_only else "No golden files found.")
        return

    # Calculate column widths
    test_col_width = max(len("Test"), max(len(t) for t in test_names))
    op_col_widths = {label: max(len(label), 12) for label in op_labels}

    for test_name in test_names:
        for label in op_labels:
            if label in results.get(test_name, {}):
                summary = results[test_name][label]["summary"]
                op_col_widths[label] = max(op_col_widths[label], len(summary))

    if markdown:
        # Markdown table
        header = f"| {'Test':<{test_col_width}} |"
        sep = f"| {'-' * test_col_width} |"
        for label in op_labels:
            w = op_col_widths[label]
            header += f" {label:<{w}} |"
            sep += f" {'-' * w} |"
        header += " Diff |"
        sep += " ---- |"

        print(header)
        print(sep)

        for test_name in test_names:
            has_diff = diffs.get(test_name, False)
            row = f"| {test_name:<{test_col_width}} |"
            for label in op_labels:
                w = op_col_widths[label]
                if label in results.get(test_name, {}):
                    summary = results[test_name][label]["summary"]
                else:
                    summary = "-"
                row += f" {summary:<{w}} |"
            diff_marker = " **!!** |" if has_diff else "      |"
            row += diff_marker
            print(row)
    else:
        # Plain text table
        header = f"{'Test':<{test_col_width}}"
        sep = "-" * test_col_width
        for label in op_labels:
            w = op_col_widths[label]
            header += f"  {label:<{w}}"
            sep += "  " + "-" * w
        header += "  Diff"
        sep += "  ----"

        print(header)
        print(sep)

        for test_name in test_names:
            has_diff = diffs.get(test_name, False)
            row = f"{test_name:<{test_col_width}}"
            for label in op_labels:
                w = op_col_widths[label]
                if label in results.get(test_name, {}):
                    summary = results[test_name][label]["summary"]
                else:
                    summary = "-"
                row += f"  {summary:<{w}}"
            diff_marker = "  <<DIFF>>" if has_diff else ""
            row += diff_marker
            print(row)

    # Summary
    total = len(test_names)
    diff_count = sum(1 for t in test_names if diffs.get(t, False))
    print()
    print(f"Total tests: {total}")
    print(f"Tests with differences: {diff_count}")
    print(f"Tests with same behavior: {total - diff_count}")

    # Show detailed diffs
    if diff_count > 0:
        print()
        print("=" * 60)
        print("DETAILED DIFFERENCES")
        print("=" * 60)
        for test_name in test_names:
            if not diffs.get(test_name, False):
                continue
            print(f"\n{test_name}:")
            for label in op_labels:
                if label in results.get(test_name, {}):
                    data = results[test_name][label]
                    msg_part = f" - {data['error_msg']}" if data["error_msg"] else ""
                    print(f"  {label:<12}: {data['summary']}{msg_part}")


def main():
    parser = argparse.ArgumentParser(description="Compare SSE-C golden files across operations")
    parser.add_argument("--markdown", action="store_true", help="Output as markdown table")
    parser.add_argument("--diff-only", action="store_true", help="Only show rows with differences")
    args = parser.parse_args()

    tests_dir = Path(__file__).parent.parent / "tests"
    if not tests_dir.exists():
        print(f"Tests directory not found: {tests_dir}", file=sys.stderr)
        sys.exit(1)

    results = load_golden_responses(tests_dir)
    if not results:
        print("No golden files found. Run tests with --record-golden first.")
        sys.exit(1)

    diffs = find_differences(results)
    print_table(results, diffs, diff_only=args.diff_only, markdown=args.markdown)


if __name__ == "__main__":
    main()
