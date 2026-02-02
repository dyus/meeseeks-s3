"""Markdown report generator for S3 compliance tests."""

from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

from .http_capture import TestHTTPData


def generate_markdown_report(
    results: list[TestHTTPData],
    output_path: Path,
    title: str = "S3 Compliance Test Report",
    group_by: str = "handler",
) -> Path:
    """Generate markdown report from test results.

    Args:
        results: List of TestHTTPData objects
        output_path: Path for output file
        title: Report title
        group_by: Grouping key ("handler" or "marker")

    Returns:
        Path to generated report
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        f"# {title}",
        "",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]

    # Summary
    passed = sum(1 for r in results if r.outcome == "passed")
    failed = sum(1 for r in results if r.outcome == "failed")
    skipped = sum(1 for r in results if r.outcome == "skipped")

    lines.extend([
        "## Summary",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Total | {len(results)} |",
        f"| Passed | {passed} |",
        f"| Failed | {failed} |",
        f"| Skipped | {skipped} |",
        "",
    ])

    # Group results
    grouped = _group_results(results, group_by)

    # Table of contents
    lines.extend([
        "## Contents",
        "",
    ])
    for group_name in sorted(grouped.keys()):
        anchor = group_name.lower().replace(" ", "-")
        count = len(grouped[group_name])
        lines.append(f"- [{group_name}](#{anchor}) ({count} tests)")
    lines.append("")

    # Detailed results by group
    lines.append("---")
    lines.append("")

    for group_name in sorted(grouped.keys()):
        group_results = grouped[group_name]
        lines.extend(_render_group(group_name, group_results))

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    return output_path


def _group_results(results: list[TestHTTPData], group_by: str) -> dict:
    """Group results by handler or marker."""
    grouped = defaultdict(list)

    for result in results:
        if group_by == "handler":
            key = result.handler or "Other"
        else:
            # Group by first non-standard marker
            key = "Other"
            for marker in result.markers:
                if marker not in ("edge_case", "slow", "aws_only", "comparison"):
                    key = marker
                    break
        grouped[key].append(result)

    return dict(grouped)


def _render_group(group_name: str, results: list[TestHTTPData]) -> list[str]:
    """Render a group of test results."""
    lines = [
        f"## {group_name}",
        "",
    ]

    for result in results:
        lines.extend(_render_test(result))

    return lines


def _render_test(result: TestHTTPData) -> list[str]:
    """Render a single test result."""
    # Status emoji
    if result.outcome == "passed":
        status = "PASS"
    elif result.outcome == "failed":
        status = "FAIL"
    else:
        status = "SKIP"

    lines = [
        f"### [{status}] {result.test_name}",
        "",
    ]

    # Markers
    if result.markers:
        markers_str = ", ".join(f"`{m}`" for m in result.markers)
        lines.append(f"**Markers:** {markers_str}")
        lines.append("")

    # Comparison mode
    if result.comparison_result:
        lines.extend(_render_comparison(result))
    # Single endpoint mode
    elif result.captures:
        for i, capture in enumerate(result.captures):
            if len(result.captures) > 1:
                lines.append(f"#### Request {i + 1}")
                lines.append("")

            lines.append("**Request:**")
            lines.append("")
            lines.append(capture.request_to_markdown())
            lines.append("")
            lines.append("**Response:**")
            lines.append("")
            lines.append(capture.response_to_markdown())
            lines.append("")

    lines.extend(["---", ""])
    return lines


def _render_comparison(result: TestHTTPData) -> list[str]:
    """Render comparison results."""
    lines = []
    comp = result.comparison_result

    # Show AWS request/response
    if result.aws_capture:
        lines.extend([
            "#### AWS",
            "",
            "**Request:**",
            "",
            result.aws_capture.request_to_markdown(),
            "",
            "**Response:**",
            "",
            result.aws_capture.response_to_markdown(),
            "",
        ])

    # Comparison table
    lines.extend([
        "#### Comparison",
        "",
        "| | AWS | Custom |",
        "|---|---|---|",
        f"| Status | {comp.get('aws_status', '-')} | {comp.get('custom_status', '-')} |",
        f"| Error | {comp.get('aws_error_code') or '-'} | {comp.get('custom_error_code') or '-'} |",
        "",
    ])

    if comp.get("is_compliant"):
        lines.append("**Compliant**")
    else:
        lines.append("**Non-compliant**")
        lines.append("")

        # Show diff
        if comp.get("body_differences"):
            lines.extend([
                "<details>",
                "<summary>Body differences</summary>",
                "",
                "```diff",
            ])
            lines.append(_format_diff(comp["body_differences"]))
            lines.extend([
                "```",
                "",
                "</details>",
            ])

    lines.append("")

    # Also show custom response if different
    if not comp.get("is_compliant") and result.custom_capture:
        lines.extend([
            "#### Custom",
            "",
            "**Response:**",
            "",
            result.custom_capture.response_to_markdown(),
            "",
        ])

    return lines


def _format_diff(differences: dict) -> str:
    """Format DeepDiff differences as diff-like output."""
    lines = []

    # Values changed
    if "values_changed" in differences:
        for path, change in differences["values_changed"].items():
            old_val = change.get("old_value", "")
            new_val = change.get("new_value", "")
            # Truncate long values
            if isinstance(old_val, str) and len(old_val) > 100:
                old_val = old_val[:100] + "..."
            if isinstance(new_val, str) and len(new_val) > 100:
                new_val = new_val[:100] + "..."
            lines.append(f"- {path}: {old_val}")
            lines.append(f"+ {path}: {new_val}")

    # Items added
    if "dictionary_item_added" in differences:
        for item in differences["dictionary_item_added"]:
            lines.append(f"+ {item}")

    # Items removed
    if "dictionary_item_removed" in differences:
        for item in differences["dictionary_item_removed"]:
            lines.append(f"- {item}")

    return "\n".join(lines) if lines else "No textual diff available"


def generate_grouped_reports(
    results: list[TestHTTPData],
    output_dir: Path,
    prefix: Optional[str] = None,
) -> list[Path]:
    """Generate separate reports for each handler group.

    Args:
        results: All test results
        output_dir: Output directory
        prefix: Filename prefix (default: current date)

    Returns:
        List of generated report paths
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    prefix = prefix or datetime.now().strftime("%Y-%m-%d")
    generated = []

    # Group by handler
    grouped = _group_results(results, "handler")

    for handler, handler_results in grouped.items():
        filename = f"{prefix}_{handler.lower().replace(' ', '_')}.md"
        path = generate_markdown_report(
            handler_results,
            output_dir / filename,
            title=f"S3 Compliance: {handler}",
        )
        generated.append(path)

    # Full report
    all_path = generate_markdown_report(
        results,
        output_dir / f"{prefix}_all.md",
        title="S3 Compliance: All Tests",
    )
    generated.append(all_path)

    return generated
