# meeseeks-s3

> *"I'm Mr. Meeseeks, look at me! I test your S3 compliance so you don't have to exist in pain!"*

A framework for testing S3-compatible storage compliance with AWS S3 API behavior.

## Why

AWS S3 API has many undocumented behaviors: error formats, edge case handling, header validation. This framework allows you to:

1. **Document AWS S3 behavior** — record exact HTTP request/response for edge cases
2. **Compare implementations** — verify your S3-compatible service behaves like AWS
3. **Regression testing** — track API behavior changes between versions

## Quick Start

```bash
# Clone and install
git clone <repo>
cd reverse_s3
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"

# Configure AWS credentials (profile: aws)
export AWS_PROFILE=aws
export TEST_BUCKET_NAME=my-test-bucket

# Run tests against AWS
pytest -m put_object
```

## Run Modes

### Single Endpoint Mode

Test a single endpoint (AWS or custom):

```bash
# Against AWS S3
pytest --endpoint=aws

# Against custom S3
export S3_ENDPOINT=https://s3.example.com
export CUSTOM_S3_PROFILE=custom-profile
pytest --endpoint=custom
```

### Comparison Mode

Compare AWS and custom endpoint simultaneously:

```bash
export S3_ENDPOINT=https://s3.example.com
export CUSTOM_S3_PROFILE=custom-profile

# Compare all tests
pytest --endpoint=both

# Compare specific test
pytest tests/put_object/test_content_md5.py -k test_invalid --endpoint=both
```

In comparison mode, a test passes only if the custom endpoint behaves identically to AWS.

## Markdown Reports

Generate reports with HTTP details:

```bash
# Generate reports with date prefix
pytest -m put_object --md-report

# Custom prefix
pytest -m put_object --md-report --md-report-prefix=v1.2.3

# Custom directory
pytest -m put_object --md-report --md-report-dir=./my-reports
```

Example report (single mode):

```markdown
### [PASS] test_invalid_content_md5_rejected

**Request:**
```http
PUT https://s3.amazonaws.com/bucket/key HTTP/1.1
Content-Type: text/plain
Content-MD5: UtIR4OcIG4EbPm25P/+HGQ==

test content
```

**Response:**
```http
HTTP/1.1 400
Content-Type: application/xml

<Error>
  <Code>BadDigest</Code>
  <Message>The Content-MD5 you specified did not match...</Message>
</Error>

```

In comparison mode, reports show both responses and diff of differences.

## Writing Tests

### Basic Structure

```python
import pytest
from s3_compliance.utils import calculate_content_md5

@pytest.mark.put_object           # Marker for filtering
@pytest.mark.s3_handler("PutObject")  # For report grouping
class TestPutObjectEdgeCases:

    @pytest.mark.edge_case
    @pytest.mark.usefixtures("setup_test_bucket")
    def test_invalid_content_md5_rejected(self, make_request, test_bucket):
        """Server should reject PutObject with invalid Content-MD5."""

        # Prepare
        body = b"test content"
        wrong_md5 = calculate_content_md5(b"different content")

        # Request
        response = make_request(
            "PUT",
            f"/{test_bucket}/test-key",
            body=body,
            headers={"Content-MD5": wrong_md5},
        )

        # Assert (works in both modes)
        if hasattr(response, "comparison"):
            # Comparison mode: check AWS first, then compliance
            assert response.aws.status_code == 400
            assert "BadDigest" in response.aws.text
            assert response.comparison.is_compliant, response.diff_summary
        else:
            # Single mode
            assert response.status_code == 400
            assert "BadDigest" in response.text
```

### The `make_request` Fixture

Universal fixture for HTTP requests:

```python
response = make_request(
    method,       # "GET", "PUT", "POST", "DELETE", "HEAD"
    path,         # "/bucket/key"
    body=b"",     # bytes
    headers={},   # dict
    query_params="",  # "?delete" or "?acl"
)
```

In single mode returns `requests.Response`.
In comparison mode returns `ComparisonResponse`:
- `response.aws` — AWS response
- `response.custom` — custom endpoint response
- `response.comparison` — comparison result
- `response.diff_summary` — text description of differences

### Available Markers

```bash
pytest -m put_object        # PutObject tests
pytest -m delete_objects    # DeleteObjects tests
pytest -m upload_part       # UploadPart tests
pytest -m post_object       # PostObject tests
pytest -m put_bucket_acl    # PutBucketACL tests
pytest -m edge_case         # All edge case tests
pytest -m slow              # Slow tests
```

### Available Fixtures

| Fixture | Description |
|---------|-------------|
| `make_request` | Universal HTTP client |
| `s3_client` | boto3 S3 client |
| `test_bucket` | Test bucket name |
| `create_test_object` | Factory for creating objects |
| `unique_key` | Unique key for test |
| `endpoint_url` | Current endpoint URL |
| `credentials` | Current endpoint credentials |

## Project Structure

```
reverse_s3/
├── src/s3_compliance/          # Library
│   ├── client.py               # S3ClientFactory
│   ├── signing.py              # SigV4 request signing
│   ├── utils.py                # MD5, SHA256 helpers
│   ├── comparison.py           # Response comparison
│   ├── http_capture.py         # HTTP capture for reports
│   └── markdown_report.py      # Markdown generator
├── tests/                      # Tests
│   ├── conftest.py             # Fixtures
│   ├── put_object/
│   │   └── test_content_md5.py
│   ├── delete_objects/
│   │   ├── test_etag_formats.py
│   │   └── test_content_length.py
│   └── ...
├── reports/                    # Generated reports
├── conftest.py                 # Global pytest hooks
└── pyproject.toml              # Configuration
```

## Environment Variables

### AWS S3 Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_PROFILE` | `aws` | AWS CLI profile name for credentials |
| `AWS_REGION` | `us-east-1` | AWS region for S3 requests |
| `AWS_S3_ENDPOINT` | `https://s3.us-east-1.amazonaws.com` | AWS S3 endpoint URL |

### Custom S3 Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `S3_ENDPOINT` | — | Custom S3 endpoint URL (**required** for custom/comparison mode) |
| `CUSTOM_S3_PROFILE` | `$AWS_PROFILE` | AWS CLI profile for custom endpoint credentials |
| `CUSTOM_S3_REGION` | `eu-west-1` | Region for custom endpoint signing |
| `S3_VERIFY_SSL` | `true` | Verify SSL certificates (`true`/`false`) |

### Test Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TEST_BUCKET_NAME` | `s3-compliance-test-bucket` | Bucket name for running tests |

### Configuring AWS Credentials

Credentials for `AWS_PROFILE` are loaded from standard AWS CLI files:

**~/.aws/credentials** — access keys:
```ini
[aws]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[custom-profile]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
```

**~/.aws/config** — region and other settings:
```ini
[profile aws]
region = us-east-1
output = json

[profile custom-profile]
region = eu-west-1
output = json
```

Create a profile via AWS CLI:
```bash
aws configure --profile aws
```

Verify current credentials:
```bash
aws sts get-caller-identity --profile aws
```

## Pytest CLI Options

```bash
pytest [options]

# Endpoint
--endpoint=aws|custom|both    # Which endpoint to test

# SSL
--no-verify-ssl               # Disable SSL verification (for self-signed certs)

# Reports
--md-report                   # Generate markdown reports
--md-report-prefix=PREFIX     # File prefix (default: date)
--md-report-dir=DIR           # Directory (default: reports/)

# Comparison
--show-comparison             # Print comparison details to console
```

## Usage Examples

### CI/CD Pipeline

```yaml
# .github/workflows/s3-compliance.yml
name: S3 Compliance
on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - run: pip install -e ".[dev]"

      - name: Test against AWS
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: pytest --endpoint=aws --md-report

      - uses: actions/upload-artifact@v4
        with:
          name: compliance-reports
          path: reports/
```

### Pre-release Comparison

```bash
# Compare all tests, save report with version
pytest --endpoint=both --md-report --md-report-prefix=v2.0.0-rc1

# Review differences
cat reports/v2.0.0-rc1_putobject.md
```

### Documenting AWS Behavior

```bash
# Run tests, record HTTP details
pytest -m edge_case --endpoint=aws --md-report --md-report-prefix=aws-behavior

# Reports in reports/aws-behavior_*.md
```

## License

MIT
