#!/usr/bin/env python3
"""Compare S3 API behavior between AWS and custom endpoint.

This script runs pytest tests in comparison mode (--endpoint=both) to compare
S3 API behavior between AWS S3 and a custom S3 implementation.

Usage:
    python scripts/compare_endpoints.py [options]

    # Run all tests in comparison mode
    python scripts/compare_endpoints.py

    # Run specific test pattern
    python scripts/compare_endpoints.py -t test_invalid_content_md5

    # Run by marker
    python scripts/compare_endpoints.py -m put_object

Environment Variables:
    AWS_PROFILE         - AWS profile for credentials (default: aws)
    AWS_S3_ENDPOINT     - AWS S3 endpoint (default: https://s3.us-east-1.amazonaws.com)
    S3_ENDPOINT         - Custom S3 endpoint URL (required)
    CUSTOM_S3_PROFILE   - Profile for custom endpoint (default: AWS_PROFILE)
    CUSTOM_S3_REGION    - Region for custom endpoint (default: eu-west-1)
    TEST_BUCKET_NAME    - Bucket name for tests (default: anon-reverse-s3-test-bucket)
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def run_pytest_comparison(
    test_pattern: str = None,
    markers: str = None,
    output_dir: Path = None,
    verbose: bool = False,
    json_report: bool = True,
    md_report: bool = False,
    md_report_prefix: str = None,
) -> tuple[bool, dict]:
    """Run pytest in comparison mode (--endpoint=both).

    Args:
        test_pattern: pytest test pattern (e.g., "test_invalid_md5" or path)
        markers: pytest marker expression (e.g., "put_object")
        output_dir: Directory for reports
        verbose: Show detailed output
        json_report: Generate JSON report
        md_report: Generate markdown report with HTTP details
        md_report_prefix: Prefix for markdown report filenames

    Returns:
        Tuple of (success: bool, report_data: dict)
    """
    output_dir = output_dir or Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build pytest command
    cmd = ["pytest", "--endpoint=both", "--no-verify-ssl"]

    if verbose:
        cmd.append("-v")

    if json_report:
        report_path = output_dir / "comparison_report.json"
        cmd.extend(["--json-report", f"--json-report-file={report_path}"])

    if md_report:
        cmd.append("--md-report")
        cmd.extend(["--md-report-dir", str(output_dir)])
        if md_report_prefix:
            cmd.extend(["--md-report-prefix", md_report_prefix])

    # Add test selection
    if markers:
        cmd.extend(["-m", markers])
    elif test_pattern:
        if "::" in test_pattern or test_pattern.endswith(".py"):
            cmd.append(test_pattern)
        else:
            cmd.extend(["-k", test_pattern])

    print("=" * 60)
    print("S3 API Compliance Comparison (pytest --endpoint=both)")
    print("=" * 60)
    print(f"AWS Endpoint:    {os.getenv('AWS_S3_ENDPOINT', 'https://s3.us-east-1.amazonaws.com')}")
    print(f"Custom Endpoint: {os.getenv('S3_ENDPOINT', 'not set')}")
    print(f"Command:         {' '.join(cmd)}")
    print("=" * 60)
    print()

    # Run pytest
    result = subprocess.run(cmd, capture_output=not verbose)

    # Load report if generated
    report_data = {}
    if json_report:
        try:
            with open(report_path) as f:
                report_data = json.load(f)
        except FileNotFoundError:
            pass

    success = result.returncode == 0
    return success, report_data


def print_comparison_summary(report_data: dict):
    """Print summary of comparison results."""
    if not report_data:
        print("No report data available")
        return

    tests = report_data.get("tests", [])
    if not tests:
        print("No tests found in report")
        return

    print()
    print("=" * 60)
    print("Comparison Summary")
    print("=" * 60)

    passed = sum(1 for t in tests if t.get("outcome") == "passed")
    failed = sum(1 for t in tests if t.get("outcome") == "failed")
    skipped = sum(1 for t in tests if t.get("outcome") == "skipped")
    total = len(tests)

    print(f"Total:   {total}")
    print(f"Passed:  {passed} (compliant)")
    print(f"Failed:  {failed} (non-compliant)")
    print(f"Skipped: {skipped}")
    print()

    if passed == total:
        print("✓ All tests passed - custom endpoint matches AWS behavior")
    elif failed > 0:
        print(f"✗ {failed} test(s) show differences between endpoints")
        print()
        print("Failed tests:")
        for t in tests:
            if t.get("outcome") == "failed":
                nodeid = t.get("nodeid", "unknown")
                short_name = nodeid.split("::")[-1] if "::" in nodeid else nodeid
                print(f"  - {short_name}")


def main():
    parser = argparse.ArgumentParser(
        description="Compare S3 API behavior between AWS and custom endpoint"
    )
    parser.add_argument(
        "--test", "-t",
        help="Test pattern or path (e.g., 'test_invalid_md5', 'tests/put_object/')",
    )
    parser.add_argument(
        "--marker", "-m",
        help="Run tests by marker (e.g., 'put_object', 'edge_case')",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="reports",
        help="Output directory for reports (default: reports)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed pytest output",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip JSON report generation",
    )
    parser.add_argument(
        "--md-report",
        action="store_true",
        help="Generate markdown report with full HTTP request/response details",
    )
    parser.add_argument(
        "--md-report-prefix",
        help="Prefix for markdown report filenames (default: current date)",
    )
    args = parser.parse_args()

    # Check required env vars
    if not os.getenv("S3_ENDPOINT"):
        print("Error: S3_ENDPOINT environment variable is required")
        print("Set it to your custom S3 endpoint URL")
        sys.exit(1)

    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Run comparison
    success, report_data = run_pytest_comparison(
        test_pattern=args.test,
        markers=args.marker,
        output_dir=Path(args.output_dir),
        verbose=args.verbose,
        json_report=not args.no_report,
        md_report=args.md_report,
        md_report_prefix=args.md_report_prefix,
    )

    # Print summary
    print_comparison_summary(report_data)

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
