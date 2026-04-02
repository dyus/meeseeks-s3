# S3 Compliance: All Tests

Generated: 2026-03-26 06:43:24

## Summary

| Metric | Count |
|--------|-------|
| Total | 134 |
| Passed | 107 |
| Failed | 27 |
| Skipped | 0 |

## Contents

- [ListObjectVersions](#listobjectversions) (134 tests)

---

## ListObjectVersions

### [PASS] test_oversized_body_with_invalid_max_keys

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

---

### [PASS] test_oversized_body_with_vid_without_key

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 1048577
x-amz-content-sha256: 154b8ed3c2383ce429058768595935faf7851b5c38db2b1732594be1d88bc05a
X-Amz-Date: 20260326T044219Z
Authorization: [REDACTED]

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
... [truncated]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 301
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>7dc066f3f65fe0aabc26a74509f3d374</RequestId>
</Error>

```

---

### [PASS] test_oversized_body_with_empty_vid

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 1048577
x-amz-content-sha256: 154b8ed3c2383ce429058768595935faf7851b5c38db2b1732594be1d88bc05a
X-Amz-Date: 20260326T044219Z
Authorization: [REDACTED]

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
... [truncated]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>b7b9966e704f897e3cc39d49a7c44e38</RequestId>
</Error>

```

---

### [PASS] test_oversized_body_with_bad_vid_format

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 1048577
x-amz-content-sha256: 154b8ed3c2383ce429058768595935faf7851b5c38db2b1732594be1d88bc05a
X-Amz-Date: 20260326T044219Z
Authorization: [REDACTED]

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
... [truncated]
```

**Response:**

```http
HTTP/1.1 500
Content-Type: application/xml
Content-Length: 241
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentValue>bad-vid</ArgumentValue>
  <ArgumentName>version-id-marker</ArgumentName>
  <RequestId>42c521d87e619b2c767f296ad9f4daf1</RequestId>
</Error>

```

---

### [PASS] test_oversized_body_with_invalid_encoding

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 1048577
x-amz-content-sha256: 154b8ed3c2383ce429058768595935faf7851b5c38db2b1732594be1d88bc05a
X-Amz-Date: 20260326T044220Z
Authorization: [REDACTED]

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
... [truncated]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 280
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>9eb2e1950aaefe5b61cf5dcc3733c2cd</RequestId>
</Error>

```

---

### [PASS] test_oversized_body_valid_query

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 1048577
x-amz-content-sha256: 154b8ed3c2383ce429058768595935faf7851b5c38db2b1732594be1d88bc05a
X-Amz-Date: 20260326T044220Z
Authorization: [REDACTED]

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
... [truncated]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 302
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_max_keys_over_encoding_type

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&max-keys=abc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044221Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentValue>abc</ArgumentValue>
  <ArgumentName>max-keys</ArgumentName>
  <RequestId>b50f18836e87df3caa934d63d8cdd7d8</RequestId>
</Error>

```

---

### [PASS] test_max_keys_over_version_id

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=k&max-keys=abc&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044221Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>001dca39bf77a025dcc08e0fad92fae8</RequestId>
</Error>

```

---

### [PASS] test_max_keys_over_dependency

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=abc&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044222Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>6f1af4ae4e5ea974d95c8302575f2e76</RequestId>
</Error>

```

---

### [PASS] test_max_keys_over_empty_vid

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=k&max-keys=abc&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044222Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentValue>abc</ArgumentValue>
  <ArgumentName>max-keys</ArgumentName>
  <RequestId>3d817d4a3760a5eee910f0cc9e0a119d</RequestId>
</Error>

```

---

### [PASS] test_max_keys_over_empty_vid_no_key

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=abc&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044223Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>ef3c89b53fd9093b620beb91b8b88242</RequestId>
</Error>

```

---

### [PASS] test_max_keys_over_empty_key_with_vid

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=&max-keys=abc&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044223Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>9b74302bd1da47b9d871e06bb12b08df</RequestId>
</Error>

```

---

### [PASS] test_empty_vid_with_key_over_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&key-marker=k&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044224Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>5811e8588729e30fa236b3eb12852bc8</RequestId>
</Error>

```

---

### [PASS] test_empty_vid_no_key_over_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044224Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 280
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>587c631f8aa4b2511653c8c87151409d</RequestId>
</Error>

```

---

### [PASS] test_empty_vid_with_empty_key_over_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&key-marker=&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044224Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 280
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>3f46874a8d0cf84322691156241ab3dc</RequestId>
</Error>

```

---

### [PASS] test_empty_vid_standalone_with_key

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044225Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>b0140506d7bb1a8e60b84bbc239177c6</RequestId>
</Error>

```

---

### [FAIL] test_empty_vid_standalone_no_key

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044225Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 302
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_dependency_over_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044226Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 301
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>367010e863758e2e8dc3222f811dc82f</RequestId>
</Error>

```

---

### [PASS] test_dependency_standalone

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044226Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 301
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>659fda4d7efe7e4bf69521eb6657baa2</RequestId>
</Error>

```

---

### [PASS] test_dependency_empty_key_over_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&key-marker=&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044227Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 301
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>7bbde61ef6dc6444fb216c43044113c8</RequestId>
</Error>

```

---

### [PASS] test_dependency_empty_key_standalone

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044227Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 301
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>633c9bd9a58942376f65d1443a202cd6</RequestId>
</Error>

```

---

### [PASS] test_dependency_empty_key_with_valid_vid

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=&version-id-marker=AElpAYzjYSpcGmodYgYGhF52bExgL7_v HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044228Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 326
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>AElpAYzjYSpcGmodYgYGhF52bExgL7_v</ArgumentValue>
  <RequestId>15666b2a372a077698adb3d2ace292b2</RequestId>
</Error>

```

---

### [FAIL] test_version_id_over_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&key-marker=k&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044228Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 280
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>41cdf86dc1cc469edfbe4b99d604b157</RequestId>
</Error>

```

---

### [FAIL] test_version_id_standalone

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=k&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044229Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 500
Content-Type: application/xml
Content-Length: 241
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentValue>bad-vid</ArgumentValue>
  <ArgumentName>version-id-marker</ArgumentName>
  <RequestId>eea382107c07b44d1a65bef84ccfd342</RequestId>
</Error>

```

---

### [PASS] test_encoding_standalone

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044229Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 280
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>c289476615431977e3aba19fae7aa32c</RequestId>
</Error>

```

---

### [PASS] test_encoding_valid_url

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=url HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044230Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 334
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <EncodingType>url</EncodingType>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_all_invalid_max_keys_wins

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&key-marker=k&max-keys=abc&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044230Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>6b7848b97cef0a2f88c16409d509059d</RequestId>
</Error>

```

---

### [FAIL] test_vid_encoding_all_invalid_vid_wins

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&key-marker=k&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044231Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 280
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>0431fe6307af34999c5c62be5e6d48e1</RequestId>
</Error>

```

---

### [PASS] test_no_key_vid_encoding_dependency_wins

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044231Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 301
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>209282b4658e46ec53c696b963d4b1c0</RequestId>
</Error>

```

---

### [PASS] test_no_key_all_invalid_max_keys_wins

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&max-keys=abc&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044232Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>2f4a54eb4284fe599d3cd3f81f35583d</RequestId>
</Error>

```

---

### [PASS] test_empty_key_empty_vid_max_keys_invalid

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=&max-keys=abc&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044232Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>da8d11c43a04cebf1e0b78ca2467f3db</RequestId>
</Error>

```

---

### [PASS] test_empty_key_bad_vid_encoding_invalid

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&key-marker=&version-id-marker=bad-vid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044233Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 301
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>5c6ba3c21c2d6166360213a877e4b0ea</RequestId>
</Error>

```

---

### [PASS] test_invalid_max_keys_returns_400[non-numeric-string]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=invalid-max-keys HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044233Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 296
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>invalid-max-keys</ArgumentValue>
  <RequestId>04b5de1916dd97aa2399629b881a756a</RequestId>
</Error>

```

---

### [PASS] test_invalid_max_keys_returns_400[alpha-string]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=abc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044234Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>819b89fe156fc6b654738cb82b9e97f3</RequestId>
</Error>

```

---

### [PASS] test_invalid_max_keys_returns_400[negative]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=-1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044234Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 282
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>-1</ArgumentValue>
  <RequestId>52456ad143588b085e043f2ca6db0231</RequestId>
</Error>

```

---

### [PASS] test_invalid_max_keys_returns_400[float]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=1.5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044234Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>1.5</ArgumentValue>
  <RequestId>3692bd9d020a2064e383186a05867875</RequestId>
</Error>

```

---

### [PASS] test_invalid_max_keys_returns_400[int32-overflow]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=2147483648 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044235Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 290
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>2147483648</ArgumentValue>
  <RequestId>d6bdd7b36989f8c90ff3204ffb6bd3a6</RequestId>
</Error>

```

---

### [FAIL] test_valid_max_keys_returns_200[zero]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=0 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044235Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 281
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>0</ArgumentValue>
  <RequestId>a2e434ef053f58beaabd093a07e490ac</RequestId>
</Error>

```

---

### [PASS] test_valid_max_keys_returns_200[one]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044236Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 299
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_valid_max_keys_returns_200[under-default]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=999 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044237Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 301
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>999</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_valid_max_keys_returns_200[default]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=1000 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044237Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 302
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_valid_max_keys_returns_200[int32-max]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=2147483647 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044238Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 308
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>2147483647</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [FAIL] test_unicode_key_marker_accepted[cjk-middle]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=%E4%B8%AD&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044238Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>32dea6bd502f9c019372d5d95658bd19</RequestId>
</Error>

```

---

### [FAIL] test_unicode_key_marker_accepted[emoji-key]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=%F0%9F%94%91&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044238Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>758aaf56a627adbe019b006130042ac4</RequestId>
</Error>

```

---

### [FAIL] test_unicode_key_marker_accepted[latin-accent]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=%C3%A9&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044239Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>7db3566c27c36f5873e40bb4ea7e041e</RequestId>
</Error>

```

---

### [PASS] test_unicode_prefix_accepted[cjk-middle]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=1&prefix=%E4%B8%AD HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044239Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 302
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>ä¸­</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_unicode_prefix_accepted[emoji-key]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=1&prefix=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044240Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 303
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>ğŸ”‘</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_unicode_prefix_accepted[latin-accent]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=1&prefix=%C3%A9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044240Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 301
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>Ã©</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [FAIL] test_unicode_version_id_marker_rejected[cjk-middle]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=some-key&max-keys=1&version-id-marker=%E4%B8%AD HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044241Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 500
Content-Type: application/xml
Content-Length: 237
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>ä¸­</ArgumentValue>
  <RequestId>bd17303ec98bf8abbdb7ee8b1c3cb88e</RequestId>
</Error>

```

---

### [FAIL] test_unicode_version_id_marker_rejected[emoji-key]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=some-key&max-keys=1&version-id-marker=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044241Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 500
Content-Type: application/xml
Content-Length: 238
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>ğŸ”‘</ArgumentValue>
  <RequestId>3a3c69745778a09171a6b4090282de98</RequestId>
</Error>

```

---

### [FAIL] test_unicode_version_id_marker_rejected[latin-accent]

**Markers:** `parametrize`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=some-key&max-keys=1&version-id-marker=%C3%A9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044241Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 500
Content-Type: application/xml
Content-Length: 236
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>Ã©</ArgumentValue>
  <RequestId>a6a58b08d469c0a5d5e0cdf50fbfeef3</RequestId>
</Error>

```

---

### [PASS] test_unicode_vid_vs_invalid_max_keys

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=k&max-keys=abc&version-id-marker=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044242Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>85a3f936859d77d6099e34e41db1d30a</RequestId>
</Error>

```

---

### [FAIL] test_unicode_vid_vs_invalid_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&key-marker=k&version-id-marker=%E4%B8%AD HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044242Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 280
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>8783e3030a58c5e5532036eecca35c67</RequestId>
</Error>

```

---

### [PASS] test_unicode_vid_vs_dependency_no_key

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&version-id-marker=%C3%A9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044243Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 296
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>Ã©</ArgumentValue>
  <RequestId>7feb56e6377cf37f90d74b436f3c9514</RequestId>
</Error>

```

---

### [FAIL] test_unicode_key_marker_vs_invalid_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&key-marker=%E4%B8%AD HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044243Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>eec2e888e944523d4fa45e54c328b8a9</RequestId>
</Error>

```

---

### [PASS] test_unicode_prefix_vs_invalid_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&prefix=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044243Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 280
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>a56a2d047f2c7ac15d8d5529a6885913</RequestId>
</Error>

```

---

### [PASS] test_unicode_prefix_vs_invalid_max_keys

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=abc&prefix=%C3%A9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044244Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>7bd54c32df81a37efb93892f55426a99</RequestId>
</Error>

```

---

### [PASS] test_unicode_key_marker_vs_invalid_max_keys

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=%F0%9F%94%91&max-keys=abc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044244Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>a4c1b3b587b7434551ac3d7407d7f910</RequestId>
</Error>

```

---

### [FAIL] test_unicode_key_and_vid_vs_invalid_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&key-marker=%E4%B8%AD&version-id-marker=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044245Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 280
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>52e2ebe9c7a078163de2d685f863ef62</RequestId>
</Error>

```

---

### [PASS] test_all_unicode_vs_invalid_max_keys

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=%E4%B8%AD&max-keys=abc&prefix=%C3%A9&version-id-marker=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044245Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>d88bd0678f1ac141da538e0554d3fabd</RequestId>
</Error>

```

---

### [PASS] test_unicode_vid_no_key_vs_invalid_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&version-id-marker=%F0%9F%94%91 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044246Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 298
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>ğŸ”‘</ArgumentValue>
  <RequestId>c134d8d07c4073fe80e75ea93e279c14</RequestId>
</Error>

```

---

### [PASS] test_unicode_vid_no_key_vs_invalid_max_keys

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=abc&version-id-marker=%E4%B8%AD HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044246Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>5df1223fa81c0965e15ad73bda7f2861</RequestId>
</Error>

```

---

### [FAIL] test_null_byte_key_marker

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=%00&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044246Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>a84309752c78d1e51fbca28a96358624</RequestId>
</Error>

```

---

### [PASS] test_null_byte_prefix

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=1&prefix=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044247Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 296
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Value must be a sequence of Unicode characters and cannot include Null.</Message>
  <ArgumentValue>ï¿½</ArgumentValue>
  <ArgumentName>prefix</ArgumentName>
  <RequestId>c0ca2bb7b5c5be42b3e71f8831253544</RequestId>
</Error>

```

---

### [FAIL] test_null_byte_delimiter

**Markers:** `edge_case`, `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&delimiter=%00&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044247Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 325
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1</MaxKeys>
  <Delimiter>ï¿½</Delimiter>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [FAIL] test_null_byte_version_id_marker_with_key

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=k&max-keys=1&version-id-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044247Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 307
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Value must be a sequence of Unicode characters and cannot include Null.</Message>
  <ArgumentValue>ï¿½</ArgumentValue>
  <ArgumentName>version-id-marker</ArgumentName>
  <RequestId>dad5a6ea6a9c1187efeca84d52a68622</RequestId>
</Error>

```

---

### [PASS] test_null_byte_version_id_marker_without_key

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&version-id-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044248Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 297
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>ï¿½</ArgumentValue>
  <RequestId>2d6b4d0d6b17738845e59c7df78928e1</RequestId>
</Error>

```

---

### [PASS] test_null_key_vs_invalid_max_keys

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=%00&max-keys=abc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044248Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>0e5d0c371c994e3cfaa9e46ec2e87a61</RequestId>
</Error>

```

---

### [PASS] test_null_prefix_vs_invalid_max_keys

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=abc&prefix=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044249Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>61da2c2dbceab27a3effa19726858575</RequestId>
</Error>

```

---

### [FAIL] test_null_key_vs_invalid_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&key-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044249Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentValue/>
  <ArgumentName>version-id-marker</ArgumentName>
  <RequestId>2ca1ecfddc8f57423dcd9b64b8a3875f</RequestId>
</Error>

```

---

### [PASS] test_null_prefix_vs_invalid_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&prefix=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044250Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 280
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>0776e4bc536296180af4e410f2109a1a</RequestId>
</Error>

```

---

### [PASS] test_null_delimiter_vs_invalid_max_keys

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&delimiter=%00&max-keys=abc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044250Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>7e2a314f37fa53058b1c2c3e31b3d90d</RequestId>
</Error>

```

---

### [PASS] test_null_delimiter_vs_invalid_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&delimiter=%00&encoding-type=invalid HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044251Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 280
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue>invalid</ArgumentValue>
  <RequestId>2aa62be67e39379f33353fb8a387a16a</RequestId>
</Error>

```

---

### [PASS] test_null_vid_with_key_vs_invalid_max_keys

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=k&max-keys=abc&version-id-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044251Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>b998d4f8ac1e9073954dc4f39af33ede</RequestId>
</Error>

```

---

### [FAIL] test_null_vid_with_key_vs_invalid_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&key-marker=k&version-id-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044252Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 307
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Value must be a sequence of Unicode characters and cannot include Null.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>ï¿½</ArgumentValue>
  <RequestId>f6429e70c9b1d3e9a4647db9d542ece0</RequestId>
</Error>

```

---

### [PASS] test_null_vid_no_key_vs_invalid_encoding

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=invalid&version-id-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044252Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 297
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>ï¿½</ArgumentValue>
  <RequestId>52a8c06f2de9f5a81750a1cbc9a7dbfd</RequestId>
</Error>

```

---

### [PASS] test_null_vid_no_key_vs_invalid_max_keys

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=abc&version-id-marker=%00 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044252Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 283
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>abc</ArgumentValue>
  <RequestId>df35a18e09e022d6d142c62bcb17f3e2</RequestId>
</Error>

```

---

### [PASS] test_list_all_versions

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044253Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 302
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [FAIL] test_list_with_max_keys_zero

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=0 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044253Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 281
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Provided max-keys not an integer or within integer range</Message>
  <ArgumentName>max-keys</ArgumentName>
  <ArgumentValue>0</ArgumentValue>
  <RequestId>d640c0847af20566043776302095379d</RequestId>
</Error>

```

---

### [PASS] test_list_with_max_keys_1

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044253Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 299
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [FAIL] test_key_marker_nonexistent_key

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=zzz-nonexistent&max-keys=5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044254Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>75a973226c15e423517f679ec94c9f08</RequestId>
</Error>

```

---

### [FAIL] test_key_marker_without_version_id_marker

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=ab&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044254Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentValue/>
  <ArgumentName>version-id-marker</ArgumentName>
  <RequestId>ceebb9791602d6d53ae3231c95df87d8</RequestId>
</Error>

```

---

### [PASS] test_delimiter_returns_common_prefixes

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&delimiter=%2F&max-keys=1000 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044255Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 326
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <Delimiter>/</Delimiter>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_delimiter_truncated_next_key_marker

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&delimiter=%2F&max-keys=1 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044255Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 323
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1</MaxKeys>
  <Delimiter>/</Delimiter>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_empty_delimiter_same_as_absent

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&delimiter=&max-keys=5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044255Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 299
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>5</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_empty_prefix_same_as_absent

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=5&prefix= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044256Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 299
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>5</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_empty_encoding_type_returns_400

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=&max-keys=5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044256Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 273
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid Encoding Method specified in Request</Message>
  <ArgumentName>encoding-type</ArgumentName>
  <ArgumentValue/>
  <RequestId>0a20463f7846a1018516b9fbf9750205</RequestId>
</Error>

```

---

### [PASS] test_empty_max_keys_treated_as_default

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044257Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 302
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_empty_version_id_marker_returns_400

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=some-key&max-keys=1&version-id-marker= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044257Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 269
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be empty.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>68d62816aa9d8f0a8aed4af599a5551b</RequestId>
</Error>

```

---

### [FAIL] test_invalid_version_id_random_string

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=some-key&max-keys=1&version-id-marker=nonexistent-version-id-12345 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044258Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 500
Content-Type: application/xml
Content-Length: 262
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>nonexistent-version-id-12345</ArgumentValue>
  <RequestId>6b5fd0eb4bd373632ce5831358c63eb9</RequestId>
</Error>

```

---

### [FAIL] test_invalid_version_id_similar_format

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=some-key&max-keys=1&version-id-marker=Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044258Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 500
Content-Type: application/xml
Content-Length: 266
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R</ArgumentValue>
  <RequestId>65e9b223326ba0d65f57fe94ab6fd875</RequestId>
</Error>

```

---

### [FAIL] test_version_id_null_is_valid

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=some-key&max-keys=1&version-id-marker=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044259Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 500
Content-Type: application/xml
Content-Length: 238
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidVersionID</Code>
  <Message/>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>null</ArgumentValue>
  <RequestId>e8bc028fd3a3029eb341be1d9fe081a1</RequestId>
</Error>

```

---

### [PASS] test_prefix_filters_results

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=100&prefix=nonexistent-prefix%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044259Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 320
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>nonexistent-prefix/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>100</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_encoding_type_url

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&encoding-type=url&max-keys=5 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044300Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 331
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>5</MaxKeys>
  <EncodingType>url</EncodingType>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_transfer_encoding_get[te_chunked]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044300Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_gzip]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: gzip
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044301Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_compress]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: compress
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044301Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_deflate]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: deflate
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044302Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_identity]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: identity
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044302Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_chunked_gzip]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, gzip
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044303Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_chunked_compress]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, compress
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044303Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_chunked_deflate]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, deflate
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044304Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_gzip_chunked]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: gzip, chunked
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044305Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_compress_chunked]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: compress, chunked
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044305Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_deflate_chunked]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: deflate, chunked
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044306Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_br]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: br
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044306Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_chunked_br]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, br
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044306Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get[te_empty_value]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044307Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 302
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_transfer_encoding_get[te_unknown]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: unknown
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044307Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_chunked]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044308Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_gzip]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: gzip
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044308Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_compress]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: compress
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044309Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_deflate]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: deflate
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044309Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_identity]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: identity
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044310Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_chunked_gzip]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, gzip
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044310Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_chunked_compress]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, compress
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044311Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_chunked_deflate]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, deflate
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044311Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_gzip_chunked]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: gzip, chunked
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044311Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_compress_chunked]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: compress, chunked
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044312Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_deflate_chunked]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: deflate, chunked
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044312Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_br]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: br
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044312Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_chunked_br]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: chunked, br
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044313Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_transfer_encoding_get_raw[te_empty_value]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044313Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 302
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_transfer_encoding_get_raw[te_unknown]

**Markers:** `usefixtures`, `parametrize`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Transfer-Encoding: unknown
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044314Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: text/html
Content-Length: 157

<html>
<head><title>400 Bad Request</title></head>
<body>
<center><h1>400 Bad Request</h1></center>
<hr><center>Angie/1.10.3</center>
</body>
</html>

```

---

### [PASS] test_both_versions_and_markers_present

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-e15b75ad%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044317Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-test-e15b75ad/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-e15b75ad/obj-alive</Key>
    <VersionId>01KMM78BFWJ9SHTSYW80VEVDH8</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:15.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-alive</Key>
    <VersionId>01KMM78AXYJ9SHTSYW80VEVDH8</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-deleted</Key>
    <VersionId>01KMM78C03WR9XZM6C2R5R9F3Y</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:16.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-revived</Key>
    <VersionId>01KMM78CX3ZGJVYS257TP8EZ9R</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:17.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-revived</Key>
    <VersionId>01KMM78CHMK7XT7DYVJ6A2YSVZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:17.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-e15b75ad/obj-deleted</Key>
    <VersionId>01KMM78CBCK7XT7DYVJ6A2YSVZ</VersionId>
    <IsL
... [truncated]
```

---

### [PASS] test_alive_object_has_two_versions

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-e15b75ad%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044317Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-test-e15b75ad/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-e15b75ad/obj-alive</Key>
    <VersionId>01KMM78BFWJ9SHTSYW80VEVDH8</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:15.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-alive</Key>
    <VersionId>01KMM78AXYJ9SHTSYW80VEVDH8</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-deleted</Key>
    <VersionId>01KMM78C03WR9XZM6C2R5R9F3Y</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:16.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-revived</Key>
    <VersionId>01KMM78CX3ZGJVYS257TP8EZ9R</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:17.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-revived</Key>
    <VersionId>01KMM78CHMK7XT7DYVJ6A2YSVZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:17.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-e15b75ad/obj-deleted</Key>
    <VersionId>01KMM78CBCK7XT7DYVJ6A2YSVZ</VersionId>
    <IsL
... [truncated]
```

---

### [PASS] test_deleted_object_has_delete_marker_as_latest

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-e15b75ad%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044318Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-test-e15b75ad/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-e15b75ad/obj-alive</Key>
    <VersionId>01KMM78BFWJ9SHTSYW80VEVDH8</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:15.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-alive</Key>
    <VersionId>01KMM78AXYJ9SHTSYW80VEVDH8</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-deleted</Key>
    <VersionId>01KMM78C03WR9XZM6C2R5R9F3Y</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:16.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-revived</Key>
    <VersionId>01KMM78CX3ZGJVYS257TP8EZ9R</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:17.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-revived</Key>
    <VersionId>01KMM78CHMK7XT7DYVJ6A2YSVZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:17.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-e15b75ad/obj-deleted</Key>
    <VersionId>01KMM78CBCK7XT7DYVJ6A2YSVZ</VersionId>
    <IsL
... [truncated]
```

---

### [PASS] test_revived_object_has_version_as_latest

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-e15b75ad%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044318Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-test-e15b75ad/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-e15b75ad/obj-alive</Key>
    <VersionId>01KMM78BFWJ9SHTSYW80VEVDH8</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:15.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-alive</Key>
    <VersionId>01KMM78AXYJ9SHTSYW80VEVDH8</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-deleted</Key>
    <VersionId>01KMM78C03WR9XZM6C2R5R9F3Y</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:16.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-revived</Key>
    <VersionId>01KMM78CX3ZGJVYS257TP8EZ9R</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:17.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-revived</Key>
    <VersionId>01KMM78CHMK7XT7DYVJ6A2YSVZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:17.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-e15b75ad/obj-deleted</Key>
    <VersionId>01KMM78CBCK7XT7DYVJ6A2YSVZ</VersionId>
    <IsL
... [truncated]
```

---

### [FAIL] test_ordering_within_same_key

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-e15b75ad%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044318Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-test-e15b75ad/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-e15b75ad/obj-alive</Key>
    <VersionId>01KMM78BFWJ9SHTSYW80VEVDH8</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:15.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-alive</Key>
    <VersionId>01KMM78AXYJ9SHTSYW80VEVDH8</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-deleted</Key>
    <VersionId>01KMM78C03WR9XZM6C2R5R9F3Y</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:16.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-revived</Key>
    <VersionId>01KMM78CX3ZGJVYS257TP8EZ9R</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:17.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-revived</Key>
    <VersionId>01KMM78CHMK7XT7DYVJ6A2YSVZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:17.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-e15b75ad/obj-deleted</Key>
    <VersionId>01KMM78CBCK7XT7DYVJ6A2YSVZ</VersionId>
    <IsL
... [truncated]
```

---

### [PASS] test_delete_marker_has_no_size_or_etag

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-e15b75ad%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044319Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Transfer-Encoding: chunked
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-test-e15b75ad/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-e15b75ad/obj-alive</Key>
    <VersionId>01KMM78BFWJ9SHTSYW80VEVDH8</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:15.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-alive</Key>
    <VersionId>01KMM78AXYJ9SHTSYW80VEVDH8</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-deleted</Key>
    <VersionId>01KMM78C03WR9XZM6C2R5R9F3Y</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:16.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-revived</Key>
    <VersionId>01KMM78CX3ZGJVYS257TP8EZ9R</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:17.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e15b75ad/obj-revived</Key>
    <VersionId>01KMM78CHMK7XT7DYVJ6A2YSVZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T04:43:17.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-e15b75ad/obj-deleted</Key>
    <VersionId>01KMM78CBCK7XT7DYVJ6A2YSVZ</VersionId>
    <IsL
... [truncated]
```

---

### [PASS] test_only_delete_markers_no_versions

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-dm-only-c31cd7cd%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044321Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 717
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-dm-only-c31cd7cd/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-c31cd7cd/dm-only-1</Key>
    <VersionId>01KMM78GCR5545FXGVBS2B64M6</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:20.000Z</LastModified>
  </DeleteMarker>
  <DeleteMarker>
    <Key>lov-dm-only-c31cd7cd/dm-only-2</Key>
    <VersionId>01KMM78GXEYNHXEH1EN9JKVBGS</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:21.000Z</LastModified>
  </DeleteMarker>
</ListVersionsResult>

```

---

### [PASS] test_delete_markers_are_all_latest

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-dm-only-c31cd7cd%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044321Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 717
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-dm-only-c31cd7cd/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-c31cd7cd/dm-only-1</Key>
    <VersionId>01KMM78GCR5545FXGVBS2B64M6</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:20.000Z</LastModified>
  </DeleteMarker>
  <DeleteMarker>
    <Key>lov-dm-only-c31cd7cd/dm-only-2</Key>
    <VersionId>01KMM78GXEYNHXEH1EN9JKVBGS</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:21.000Z</LastModified>
  </DeleteMarker>
</ListVersionsResult>

```

---

### [FAIL] test_delete_markers_have_owner_and_version_id

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-dm-only-c31cd7cd%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044321Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 717
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-dm-only-c31cd7cd/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-c31cd7cd/dm-only-1</Key>
    <VersionId>01KMM78GCR5545FXGVBS2B64M6</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:20.000Z</LastModified>
  </DeleteMarker>
  <DeleteMarker>
    <Key>lov-dm-only-c31cd7cd/dm-only-2</Key>
    <VersionId>01KMM78GXEYNHXEH1EN9JKVBGS</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:21.000Z</LastModified>
  </DeleteMarker>
</ListVersionsResult>

```

---

### [PASS] test_only_markers_with_max_keys_1

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=1&prefix=lov-dm-only-c31cd7cd%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260326T044322Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 646
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-dm-only-c31cd7cd/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <NextKeyMarker>lov-dm-only-c31cd7cd/dm-only-1</NextKeyMarker>
  <NextVersionIdMarker>01KMM78GCR5545FXGVBS2B64M6</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-c31cd7cd/dm-only-1</Key>
    <VersionId>01KMM78GCR5545FXGVBS2B64M6</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T04:43:20.000Z</LastModified>
  </DeleteMarker>
</ListVersionsResult>

```

---
