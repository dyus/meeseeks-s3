"""Report generation for S3 compliance testing.

Generates HTML and JSON reports from comparison results.
"""

import json
from datetime import datetime
from html import escape as html_escape
from pathlib import Path
from typing import Union

from s3_compliance.comparison import ComparisonSummary, ComparisonResult


def generate_json_report(
    summary: ComparisonSummary,
    output_path: Union[str, Path],
    aws_endpoint: str = "AWS S3",
    custom_endpoint: str = "Custom S3",
) -> Path:
    """Generate JSON report from comparison summary.

    Args:
        summary: ComparisonSummary with all results
        output_path: Path to write JSON report
        aws_endpoint: Description of AWS endpoint
        custom_endpoint: Description of custom endpoint

    Returns:
        Path to generated report
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "aws_endpoint": aws_endpoint,
            "custom_endpoint": custom_endpoint,
        },
        **summary.to_dict(),
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return output_path


def generate_html_report(
    summary: ComparisonSummary,
    output_path: Union[str, Path],
    aws_endpoint: str = "AWS S3",
    custom_endpoint: str = "Custom S3",
) -> Path:
    """Generate HTML report from comparison summary.

    Args:
        summary: ComparisonSummary with all results
        output_path: Path to write HTML report
        aws_endpoint: Description of AWS endpoint
        custom_endpoint: Description of custom endpoint

    Returns:
        Path to generated report
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    html = _generate_html(summary, aws_endpoint, custom_endpoint)

    with open(output_path, "w") as f:
        f.write(html)

    return output_path


def _generate_html(
    summary: ComparisonSummary,
    aws_endpoint: str,
    custom_endpoint: str,
) -> str:
    """Generate HTML content for comparison report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Generate results rows
    rows = []
    for result in summary.results:
        status_class = "success" if result.is_compliant else "failure"
        if result.compliance_level == "PARTIAL":
            status_class = "warning"

        diff_details = ""
        if result.body_differences:
            # Escape JSON content to prevent XSS
            escaped_json = html_escape(json.dumps(result.body_differences, indent=2, default=str))
            diff_details = f"<pre>{escaped_json}</pre>"

        # Escape all user-controlled content to prevent XSS
        rows.append(f"""
        <tr class="{status_class}">
            <td>{html_escape(result.test_name)}</td>
            <td>{result.aws_status}</td>
            <td>{result.custom_status}</td>
            <td>{"Yes" if result.status_match else "No"}</td>
            <td>{html_escape(result.aws_error_code) if result.aws_error_code else "-"}</td>
            <td>{html_escape(result.custom_error_code) if result.custom_error_code else "-"}</td>
            <td>{"Yes" if result.error_code_match else "No"}</td>
            <td>{html_escape(result.compliance_level)}</td>
            <td class="diff-cell">{diff_details if diff_details else "-"}</td>
        </tr>
        """)

    # Non-compliant summary
    non_compliant = summary.get_non_compliant()
    non_compliant_section = ""
    if non_compliant:
        # Escape all user-controlled content to prevent XSS
        nc_items = "\n".join(
            f"<li><strong>{html_escape(r.test_name)}</strong>: "
            f"AWS={r.aws_status} vs Custom={r.custom_status}, "
            f"Error: {html_escape(r.aws_error_code or '-')} vs {html_escape(r.custom_error_code or '-')}</li>"
            for r in non_compliant
        )
        non_compliant_section = f"""
        <div class="non-compliant-section">
            <h3>Non-Compliant Tests ({len(non_compliant)})</h3>
            <ul>{nc_items}</ul>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>S3 Compliance Report</title>
    <style>
        :root {{
            --success: #28a745;
            --warning: #ffc107;
            --failure: #dc3545;
            --bg-light: #f8f9fa;
            --border: #dee2e6;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: var(--bg-light);
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 2px solid var(--border);
            padding-bottom: 15px;
        }}
        .metadata {{
            background: var(--bg-light);
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .summary-card.total {{ background: #e9ecef; }}
        .summary-card.compliant {{ background: #d4edda; color: var(--success); }}
        .summary-card.partial {{ background: #fff3cd; color: #856404; }}
        .summary-card.non-compliant {{ background: #f8d7da; color: var(--failure); }}
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
        }}
        .summary-card .label {{
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #343a40;
            color: white;
            font-weight: 500;
        }}
        tr.success {{ background: #d4edda; }}
        tr.warning {{ background: #fff3cd; }}
        tr.failure {{ background: #f8d7da; }}
        tr:hover {{ opacity: 0.9; }}
        .diff-cell {{
            max-width: 400px;
            overflow: auto;
        }}
        .diff-cell pre {{
            margin: 0;
            font-size: 0.8em;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .non-compliant-section {{
            background: #fff3cd;
            padding: 20px;
            border-radius: 8px;
            margin-top: 30px;
        }}
        .non-compliant-section h3 {{
            margin-top: 0;
            color: #856404;
        }}
        .compliance-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        .compliance-badge.high {{ background: var(--success); color: white; }}
        .compliance-badge.medium {{ background: var(--warning); color: #333; }}
        .compliance-badge.low {{ background: var(--failure); color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>S3 API Compliance Report</h1>

        <div class="metadata">
            <strong>Generated:</strong> {html_escape(timestamp)}<br>
            <strong>AWS Endpoint:</strong> {html_escape(aws_endpoint)}<br>
            <strong>Custom Endpoint:</strong> {html_escape(custom_endpoint)}
        </div>

        <div class="summary">
            <div class="summary-card total">
                <div class="number">{summary.total}</div>
                <div class="label">Total Tests</div>
            </div>
            <div class="summary-card compliant">
                <div class="number">{summary.compliant_count}</div>
                <div class="label">Compliant</div>
            </div>
            <div class="summary-card partial">
                <div class="number">{summary.partial_count}</div>
                <div class="label">Partial</div>
            </div>
            <div class="summary-card non-compliant">
                <div class="number">{summary.non_compliant_count}</div>
                <div class="label">Non-Compliant</div>
            </div>
        </div>

        <p>
            <strong>Compliance Rate:</strong>
            <span class="compliance-badge {'high' if summary.compliance_rate >= 90 else 'medium' if summary.compliance_rate >= 70 else 'low'}">
                {summary.compliance_rate:.1f}%
            </span>
        </p>

        {non_compliant_section}

        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Test Name</th>
                    <th>AWS Status</th>
                    <th>Custom Status</th>
                    <th>Status Match</th>
                    <th>AWS Error</th>
                    <th>Custom Error</th>
                    <th>Error Match</th>
                    <th>Compliance</th>
                    <th>Differences</th>
                </tr>
            </thead>
            <tbody>
                {"".join(rows)}
            </tbody>
        </table>
    </div>
</body>
</html>"""


def print_summary(summary: ComparisonSummary) -> None:
    """Print comparison summary to console."""
    print("\n" + "=" * 70)
    print("S3 COMPLIANCE SUMMARY")
    print("=" * 70)
    print(f"Total Tests:    {summary.total}")
    print(f"Compliant:      {summary.compliant_count}")
    print(f"Partial:        {summary.partial_count}")
    print(f"Non-Compliant:  {summary.non_compliant_count}")
    print(f"Compliance Rate: {summary.compliance_rate:.1f}%")

    non_compliant = summary.get_non_compliant()
    if non_compliant:
        print("\n" + "-" * 70)
        print("NON-COMPLIANT TESTS:")
        print("-" * 70)
        for result in non_compliant:
            print(f"\n  {result.test_name}")
            print(f"    AWS:    {result.aws_status} / {result.aws_error_code or 'OK'}")
            print(f"    Custom: {result.custom_status} / {result.custom_error_code or 'OK'}")
            if result.body_differences:
                print(f"    Diff:   {list(result.body_differences.keys())}")

    print("\n" + "=" * 70)
