# S3 Compliance: All Tests

Generated: 2026-04-01 08:00:15

## Summary

| Metric | Count |
|--------|-------|
| Total | 137 |
| Passed | 136 |
| Failed | 1 |
| Skipped | 0 |

## Contents

- [ListObjectVersions](#listobjectversions) (137 tests)

---

## ListObjectVersions

### [PASS] test_oversized_body_with_invalid_max_keys

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=abc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 1048577
x-amz-content-sha256: 154b8ed3c2383ce429058768595935faf7851b5c38db2b1732594be1d88bc05a
X-Amz-Date: 20260401T055803Z
Authorization: [REDACTED]

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
... [truncated]
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
  <RequestId>916e27c9a3adc74e5c27b4d7a5bcb736</RequestId>
</Error>

```

---

### [PASS] test_oversized_body_with_vid_without_key

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

---

### [PASS] test_oversized_body_with_empty_vid

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

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
X-Amz-Date: 20260401T055806Z
Authorization: [REDACTED]

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
... [truncated]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 260
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>82a8f652f6984975548c66176b69f5aa</RequestId>
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
X-Amz-Date: 20260401T055806Z
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
  <RequestId>32532316d35f1ca1a02aadbe887dbc24</RequestId>
</Error>

```

---

### [PASS] test_oversized_body_valid_query

**Markers:** `usefixtures`, `edge_case`, `s3_handler`, `list_object_versions`

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
X-Amz-Date: 20260401T055808Z
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
  <RequestId>067d7defc5f401f9aef0adc5a10d2710</RequestId>
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
X-Amz-Date: 20260401T055808Z
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
  <RequestId>00753081c024f910afcee1ab6073a100</RequestId>
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
X-Amz-Date: 20260401T055809Z
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
  <RequestId>b68352dd62bc43d9501661113c46f7a5</RequestId>
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
X-Amz-Date: 20260401T055810Z
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
  <RequestId>db8af4712ed24538bfc3a42529d37017</RequestId>
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
X-Amz-Date: 20260401T055811Z
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
  <RequestId>4ad285a8c15d49b0c041ae3b51dc4d7d</RequestId>
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
X-Amz-Date: 20260401T055812Z
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
  <RequestId>6fae9498a6c78c3342263adda6dfebdc</RequestId>
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
X-Amz-Date: 20260401T055813Z
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
  <RequestId>7d0faff5518c4238741c0dd17aedbf54</RequestId>
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
X-Amz-Date: 20260401T055816Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 294
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>63abd72e848f8ba2faa68687750ddde0</RequestId>
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
X-Amz-Date: 20260401T055816Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 294
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>509b3b8f417a3ec6846cbddde05cc9a3</RequestId>
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
X-Amz-Date: 20260401T055817Z
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
  <RequestId>823e90181847358f84a65a115ef668a8</RequestId>
</Error>

```

---

### [PASS] test_empty_vid_standalone_no_key

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
X-Amz-Date: 20260401T055818Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 294
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>A version-id marker cannot be specified without a key marker.</Message>
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue/>
  <RequestId>14158b6984f5aa33d824a0a6925c2ff5</RequestId>
</Error>

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
X-Amz-Date: 20260401T055819Z
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
  <RequestId>23217177267fef6e5832d64a9bf1459a</RequestId>
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
X-Amz-Date: 20260401T055820Z
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
  <RequestId>c6b7c584c7deea50c6b80e9aab0f936b</RequestId>
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
X-Amz-Date: 20260401T055822Z
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
  <RequestId>e3b487f7a91df21040045fef5ba4008f</RequestId>
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
X-Amz-Date: 20260401T055823Z
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
  <RequestId>d4a6bbd054d8b295a6f24b5f1c25f68c</RequestId>
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
X-Amz-Date: 20260401T055826Z
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
  <RequestId>3c4ca5f81559d828a167d43deec2efc6</RequestId>
</Error>

```

---

### [PASS] test_version_id_over_encoding

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
X-Amz-Date: 20260401T055827Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 260
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>588b3147da9f8e7f73adc2094d9f18b5</RequestId>
</Error>

```

---

### [PASS] test_version_id_standalone

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
X-Amz-Date: 20260401T055827Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 260
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>7ac4ca4794613ea227c2e7b9cc81d606</RequestId>
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
X-Amz-Date: 20260401T055828Z
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
  <ArgumentValue>invalid</ArgumentValue>
  <ArgumentName>encoding-type</ArgumentName>
  <RequestId>946f90e7c7a3faf72f8bf8f391eb97c6</RequestId>
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
X-Amz-Date: 20260401T055829Z
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
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <EncodingType>url</EncodingType>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6T4XRFTJ3PVWRHJYC2HZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:19.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6V4FAYC4QEKQCQV6705J</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6TS69Q5EKHBF2K5VNTQZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-revived</Key>
    <VersionId>01KMMB6VQGNSCK9WTKN2GV5909</VersionId>
... [truncated]
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
X-Amz-Date: 20260401T055829Z
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
  <RequestId>b910aaa06b318b801a3eaf4e2b1a5655</RequestId>
</Error>

```

---

### [PASS] test_vid_encoding_all_invalid_vid_wins

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
X-Amz-Date: 20260401T055830Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 260
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>8d2a30dba58a1a4ee92867aabfbce6a7</RequestId>
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
X-Amz-Date: 20260401T055831Z
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
  <ArgumentValue>bad-vid</ArgumentValue>
  <ArgumentName>version-id-marker</ArgumentName>
  <RequestId>6248c5117f7aa9e876fbea104f1525b6</RequestId>
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
X-Amz-Date: 20260401T055832Z
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
  <RequestId>d8408890e96895af6856978c80c7794e</RequestId>
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
X-Amz-Date: 20260401T055833Z
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
  <RequestId>66c5357b3d346dc86c154e80e08045a4</RequestId>
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
X-Amz-Date: 20260401T055834Z
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
  <RequestId>cd1974b51c3feebadb04cd0b9eb3dcb3</RequestId>
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
X-Amz-Date: 20260401T055835Z
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
  <ArgumentValue>invalid-max-keys</ArgumentValue>
  <ArgumentName>max-keys</ArgumentName>
  <RequestId>88c4c79ccfdec0a66ce53932654e21c8</RequestId>
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
X-Amz-Date: 20260401T055836Z
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
  <RequestId>2146b15a84a6a4053d1477ce091b4611</RequestId>
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
X-Amz-Date: 20260401T055837Z
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
  <RequestId>b7c83048128aaf456e387af129e49f91</RequestId>
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
X-Amz-Date: 20260401T055837Z
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
  <RequestId>f4d19c0ceb630d47c8d26459d294d504</RequestId>
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
X-Amz-Date: 20260401T055838Z
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
  <ArgumentValue>2147483648</ArgumentValue>
  <ArgumentName>max-keys</ArgumentName>
  <RequestId>fb24bdf169612d3892581927b126aae1</RequestId>
</Error>

```

---

### [PASS] test_valid_max_keys_returns_200[zero]

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
X-Amz-Date: 20260401T055839Z
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
  <VersionIdMarker/>
  <MaxKeys>0</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

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
X-Amz-Date: 20260401T055840Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 809
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>lov-compare-025e1792-obj-alive</NextKeyMarker>
  <NextVersionIdMarker>01KMMB6TGT29B2TPDPXNNS54F4</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
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
X-Amz-Date: 20260401T055841Z
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
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>999</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6T4XRFTJ3PVWRHJYC2HZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:19.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6V4FAYC4QEKQCQV6705J</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6TS69Q5EKHBF2K5VNTQZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-revived</Key>
    <VersionId>01KMMB6VQGNSCK9WTKN2GV5909</VersionId>
    <IsLatest>true</IsLatest>
    <
... [truncated]
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
X-Amz-Date: 20260401T055842Z
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
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6T4XRFTJ3PVWRHJYC2HZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:19.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6V4FAYC4QEKQCQV6705J</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6TS69Q5EKHBF2K5VNTQZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-revived</Key>
    <VersionId>01KMMB6VQGNSCK9WTKN2GV5909</VersionId>
    <IsLatest>true</IsLatest>
    
... [truncated]
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
X-Amz-Date: 20260401T055844Z
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
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>2147483647</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6T4XRFTJ3PVWRHJYC2HZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:19.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6V4FAYC4QEKQCQV6705J</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6TS69Q5EKHBF2K5VNTQZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-revived</Key>
    <VersionId>01KMMB6VQGNSCK9WTKN2GV5909</VersionId>
    <IsLatest>true</IsLatest
... [truncated]
```

---

### [PASS] test_unicode_key_marker_accepted[cjk-middle]

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
X-Amz-Date: 20260401T055844Z
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
  <KeyMarker>ä¸­</KeyMarker>
  <VersionIdMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_unicode_key_marker_accepted[emoji-key]

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
X-Amz-Date: 20260401T055845Z
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
  <Prefix/>
  <KeyMarker>ğŸ”‘</KeyMarker>
  <VersionIdMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_unicode_key_marker_accepted[latin-accent]

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
X-Amz-Date: 20260401T055846Z
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
  <KeyMarker>Ã©</KeyMarker>
  <VersionIdMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

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
X-Amz-Date: 20260401T055847Z
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
  <VersionIdMarker/>
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
X-Amz-Date: 20260401T055848Z
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
  <VersionIdMarker/>
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
X-Amz-Date: 20260401T055849Z
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
  <VersionIdMarker/>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_unicode_version_id_marker_rejected[cjk-middle]

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
X-Amz-Date: 20260401T055850Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 256
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>ä¸­</ArgumentValue>
  <RequestId>098dd5a31995a7a5fe312a6ff74822d4</RequestId>
</Error>

```

---

### [PASS] test_unicode_version_id_marker_rejected[emoji-key]

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
X-Amz-Date: 20260401T055851Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 257
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>ðŸ”‘</ArgumentValue>
  <RequestId>dc926ef867eddf4f15fc4f99da6b0a18</RequestId>
</Error>

```

---

### [PASS] test_unicode_version_id_marker_rejected[latin-accent]

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
X-Amz-Date: 20260401T055852Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 255
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentValue>Ã©</ArgumentValue>
  <ArgumentName>versionId</ArgumentName>
  <RequestId>92ff84ba0357fbca211e5648e1305f05</RequestId>
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
X-Amz-Date: 20260401T055853Z
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
  <RequestId>2f53ac3d939bebcf2e4df97f173ddf35</RequestId>
</Error>

```

---

### [PASS] test_unicode_vid_vs_invalid_encoding

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
X-Amz-Date: 20260401T055853Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 256
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>ä¸­</ArgumentValue>
  <RequestId>20cfa79d9f50c9d1b87989beac9d6d7b</RequestId>
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
X-Amz-Date: 20260401T055854Z
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
  <RequestId>e8079858fae890679daef6b2e67edd66</RequestId>
</Error>

```

---

### [PASS] test_unicode_key_marker_vs_invalid_encoding

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
X-Amz-Date: 20260401T055855Z
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
  <RequestId>9a5b99d14146a230acbfe0ad64987b39</RequestId>
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
X-Amz-Date: 20260401T055855Z
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
  <RequestId>9602005ea81db5645951a38103b7ae48</RequestId>
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
X-Amz-Date: 20260401T055856Z
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
  <RequestId>27edca77910b74baa17f02a9b153d87f</RequestId>
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
X-Amz-Date: 20260401T055856Z
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
  <RequestId>73152ab98a2a1e2f06c2baac55cc26b4</RequestId>
</Error>

```

---

### [PASS] test_unicode_key_and_vid_vs_invalid_encoding

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
X-Amz-Date: 20260401T055857Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 257
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>ðŸ”‘</ArgumentValue>
  <RequestId>adcf5e00b542f86c5bf6a4ea56b1d69b</RequestId>
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
X-Amz-Date: 20260401T055858Z
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
  <RequestId>9d2a9bf1c64d666d5ece7dca3f0b2850</RequestId>
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
X-Amz-Date: 20260401T055858Z
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
  <RequestId>ba1a766f07a94f3629c679174970e8cb</RequestId>
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
X-Amz-Date: 20260401T055900Z
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
  <RequestId>c3d7eb4330cf80f636351204e9b8206e</RequestId>
</Error>

```

---

### [PASS] test_null_byte_key_marker

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
X-Amz-Date: 20260401T055901Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 300
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Value must be a sequence of Unicode characters and cannot include Null.</Message>
  <ArgumentValue>ï¿½</ArgumentValue>
  <ArgumentName>key-marker</ArgumentName>
  <RequestId>159c68a2e74803c3a8515770cbb7b44a</RequestId>
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
X-Amz-Date: 20260401T055902Z
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
  <ArgumentName>prefix</ArgumentName>
  <ArgumentValue>ï¿½</ArgumentValue>
  <RequestId>eff1ead5a8b2958a8d9d4b652b041465</RequestId>
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
X-Amz-Date: 20260401T055903Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 299
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Value must be a sequence of Unicode characters and cannot include Null.</Message>
  <ArgumentName>delimiter</ArgumentName>
  <ArgumentValue>ï¿½</ArgumentValue>
  <RequestId>1a350e1d0d17c00341d8bee8f89db00c</RequestId>
</Error>

```

---

### [PASS] test_null_byte_version_id_marker_with_key

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
X-Amz-Date: 20260401T055904Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 256
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>ï¿½</ArgumentValue>
  <RequestId>fdfc25c0bb478f75063833a70b877624</RequestId>
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
X-Amz-Date: 20260401T055905Z
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
  <RequestId>3b41fcee393951c70e5f530abd2894bb</RequestId>
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
X-Amz-Date: 20260401T055906Z
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
  <RequestId>acb5b92f7f4942fb2df31cf9f376d0e1</RequestId>
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
X-Amz-Date: 20260401T055907Z
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
  <RequestId>9d7735c3ddf841c1853be3f29f3dce58</RequestId>
</Error>

```

---

### [PASS] test_null_key_vs_invalid_encoding

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
X-Amz-Date: 20260401T055908Z
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
  <RequestId>39dcc005abf0f5f76169dba699e9a85d</RequestId>
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
X-Amz-Date: 20260401T055908Z
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
  <RequestId>93abe688e78a64fdbddc12af8ea18094</RequestId>
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
X-Amz-Date: 20260401T055909Z
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
  <RequestId>9e300a93611021b10d13a7f010288f83</RequestId>
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
X-Amz-Date: 20260401T055910Z
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
  <RequestId>7af32df3d0f1a5401ab99e51ce046750</RequestId>
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
X-Amz-Date: 20260401T055912Z
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
  <RequestId>e693dac79185da7482c5a8affbc5adcb</RequestId>
</Error>

```

---

### [PASS] test_null_vid_with_key_vs_invalid_encoding

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
X-Amz-Date: 20260401T055913Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 256
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>ï¿½</ArgumentValue>
  <RequestId>7ae6fb21f58231d71091310fd0efc383</RequestId>
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
X-Amz-Date: 20260401T055914Z
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
  <RequestId>1621fe0e4d96c7326dde77c907180613</RequestId>
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
X-Amz-Date: 20260401T055914Z
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
  <RequestId>d3e7e5ddb4e1081006a8309c14fdf39d</RequestId>
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
X-Amz-Date: 20260401T055915Z
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
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6T4XRFTJ3PVWRHJYC2HZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:19.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6V4FAYC4QEKQCQV6705J</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6TS69Q5EKHBF2K5VNTQZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-revived</Key>
    <VersionId>01KMMB6VQGNSCK9WTKN2GV5909</VersionId>
    <IsLatest>true</IsLatest>
    
... [truncated]
```

---

### [PASS] test_list_with_max_keys_zero

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
X-Amz-Date: 20260401T055916Z
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
  <VersionIdMarker/>
  <MaxKeys>0</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

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
X-Amz-Date: 20260401T055917Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 809
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>lov-compare-025e1792-obj-alive</NextKeyMarker>
  <NextVersionIdMarker>01KMMB6TGT29B2TPDPXNNS54F4</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
</ListVersionsResult>

```

---

### [PASS] test_key_marker_nonexistent_key

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
X-Amz-Date: 20260401T055917Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 314
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker>zzz-nonexistent</KeyMarker>
  <VersionIdMarker/>
  <MaxKeys>5</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_key_marker_without_version_id_marker

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
X-Amz-Date: 20260401T055918Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 811
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker>ab</KeyMarker>
  <VersionIdMarker/>
  <NextKeyMarker>lov-compare-025e1792-obj-alive</NextKeyMarker>
  <NextVersionIdMarker>01KMMB6TGT29B2TPDPXNNS54F4</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
</ListVersionsResult>

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
X-Amz-Date: 20260401T055919Z
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
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <Delimiter>/</Delimiter>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6T4XRFTJ3PVWRHJYC2HZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:19.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6V4FAYC4QEKQCQV6705J</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6TS69Q5EKHBF2K5VNTQZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-revived</Key>
    <VersionId>01KMMB6VQGNSCK9WTKN2GV5909</VersionId>
    <Is
... [truncated]
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
X-Amz-Date: 20260401T055919Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 833
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>lov-compare-025e1792-obj-alive</NextKeyMarker>
  <NextVersionIdMarker>01KMMB6TGT29B2TPDPXNNS54F4</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <Delimiter>/</Delimiter>
  <IsTruncated>true</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
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
X-Amz-Date: 20260401T055920Z
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
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>lov-compare-025e1792-obj-revived</NextKeyMarker>
  <NextVersionIdMarker>01KMMB6VQGNSCK9WTKN2GV5909</NextVersionIdMarker>
  <MaxKeys>5</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6T4XRFTJ3PVWRHJYC2HZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:19.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6V4FAYC4QEKQCQV6705J</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6TS69Q5EKHBF2K5VNTQZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
  
... [truncated]
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
X-Amz-Date: 20260401T055920Z
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
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>lov-compare-025e1792-obj-revived</NextKeyMarker>
  <NextVersionIdMarker>01KMMB6VQGNSCK9WTKN2GV5909</NextVersionIdMarker>
  <MaxKeys>5</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6T4XRFTJ3PVWRHJYC2HZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:19.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6V4FAYC4QEKQCQV6705J</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6TS69Q5EKHBF2K5VNTQZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
  
... [truncated]
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
X-Amz-Date: 20260401T055921Z
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
  <RequestId>d10844b6509e3ab180747cffdc131348</RequestId>
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
X-Amz-Date: 20260401T055922Z
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
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6T4XRFTJ3PVWRHJYC2HZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:19.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6V4FAYC4QEKQCQV6705J</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6TS69Q5EKHBF2K5VNTQZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-revived</Key>
    <VersionId>01KMMB6VQGNSCK9WTKN2GV5909</VersionId>
    <IsLatest>true</IsLatest>
    
... [truncated]
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
X-Amz-Date: 20260401T055923Z
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
  <RequestId>7cdb6e58b4688489d538a582eb125d1d</RequestId>
</Error>

```

---

### [PASS] test_invalid_version_id_random_string

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
X-Amz-Date: 20260401T055923Z
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
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>nonexistent-version-id-12345</ArgumentValue>
  <RequestId>15f2578c04a6538d3ea19f4eb3f3596a</RequestId>
</Error>

```

---

### [PASS] test_invalid_version_id_similar_format

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
X-Amz-Date: 20260401T055924Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 285
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Invalid version id specified</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue>Eyn7lxdGE1WU1SU6QTbW1X6cbSIIRY0R</ArgumentValue>
  <RequestId>a5770e4a074f2198eb28d4bd4fd89bd5</RequestId>
</Error>

```

---

### [PASS] test_version_id_null_is_valid

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
X-Amz-Date: 20260401T055925Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 311
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker>some-key</KeyMarker>
  <VersionIdMarker>null</VersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_vid_null_returns_objects_after_key_marker

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=lov-test-b96e7053%2Fobj-alive&prefix=lov-test-b96e7053%2F&version-id-marker=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T055929Z
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
  <Prefix>lov-test-b96e7053/</Prefix>
  <KeyMarker>lov-test-b96e7053/obj-alive</KeyMarker>
  <VersionIdMarker>null</VersionIdMarker>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-test-b96e7053/obj-deleted</Key>
    <VersionId>01KN3T06TPEVQPAYVFSFCC8R7Q</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T05:59:28.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-b96e7053/obj-deleted</Key>
    <VersionId>01KN3T06DBWAF0WWQ0Q4Q315JG</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T05:59:28.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-b96e7053/obj-revived</Key>
    <VersionId>01KN3T07PVSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T05:59:29.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-b96e7053/obj-revived</Key>
    <VersionId>01KN3T07GYEVQPAYVFSFCC8R7Q</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T05:59:29.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-b96e7053/obj-revived</Key>
    <VersionId>01KN3T071AEVQPAYVFSFCC8R7Q</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T05
... [truncated]
```

---

### [PASS] test_vid_null_with_last_key_returns_empty

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=lov-test-b96e7053%2Fobj-revived&prefix=lov-test-b96e7053%2F&version-id-marker=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T055930Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 353
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-test-b96e7053/</Prefix>
  <KeyMarker>lov-test-b96e7053/obj-revived</KeyMarker>
  <VersionIdMarker>null</VersionIdMarker>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

```

---

### [PASS] test_vid_null_with_nonexistent_key

**Markers:** `usefixtures`, `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&key-marker=zzz-nonexistent-key&max-keys=5&version-id-marker=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T055931Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 322
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix/>
  <KeyMarker>zzz-nonexistent-key</KeyMarker>
  <VersionIdMarker>null</VersionIdMarker>
  <MaxKeys>5</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>

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
X-Amz-Date: 20260401T055932Z
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
  <VersionIdMarker/>
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
X-Amz-Date: 20260401T055932Z
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
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>lov-compare-025e1792-obj-revived</NextKeyMarker>
  <NextVersionIdMarker>01KMMB6VQGNSCK9WTKN2GV5909</NextVersionIdMarker>
  <MaxKeys>5</MaxKeys>
  <EncodingType>url</EncodingType>
  <IsTruncated>true</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6T4XRFTJ3PVWRHJYC2HZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:19.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6V4FAYC4QEKQCQV6705J</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6TS69Q5EKHBF2K5VNTQZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</Storag
... [truncated]
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
X-Amz-Date: 20260401T055935Z
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
X-Amz-Date: 20260401T055936Z
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
X-Amz-Date: 20260401T055936Z
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
X-Amz-Date: 20260401T055937Z
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
X-Amz-Date: 20260401T055938Z
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
X-Amz-Date: 20260401T055938Z
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
X-Amz-Date: 20260401T055940Z
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
X-Amz-Date: 20260401T055940Z
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
X-Amz-Date: 20260401T055941Z
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
X-Amz-Date: 20260401T055941Z
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
X-Amz-Date: 20260401T055942Z
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
X-Amz-Date: 20260401T055943Z
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
X-Amz-Date: 20260401T055944Z
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
X-Amz-Date: 20260401T055945Z
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
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6T4XRFTJ3PVWRHJYC2HZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:19.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6V4FAYC4QEKQCQV6705J</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6TS69Q5EKHBF2K5VNTQZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-revived</Key>
    <VersionId>01KMMB6VQGNSCK9WTKN2GV5909</VersionId>
    <IsLatest>true</IsLatest>
    
... [truncated]
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
X-Amz-Date: 20260401T055945Z
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
X-Amz-Date: 20260401T055946Z
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
X-Amz-Date: 20260401T055947Z
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
X-Amz-Date: 20260401T055948Z
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
X-Amz-Date: 20260401T055949Z
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
X-Amz-Date: 20260401T055949Z
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
X-Amz-Date: 20260401T055951Z
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
X-Amz-Date: 20260401T055952Z
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
X-Amz-Date: 20260401T055952Z
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
X-Amz-Date: 20260401T055953Z
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
X-Amz-Date: 20260401T055954Z
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
X-Amz-Date: 20260401T055954Z
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
X-Amz-Date: 20260401T055955Z
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
X-Amz-Date: 20260401T055956Z
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
X-Amz-Date: 20260401T055958Z
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
  <Prefix/>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6TGT29B2TPDPXNNS54F4</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-alive</Key>
    <VersionId>01KMMB6T4XRFTJ3PVWRHJYC2HZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:19.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6V4FAYC4QEKQCQV6705J</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-compare-025e1792-obj-deleted</Key>
    <VersionId>01KMMB6TS69Q5EKHBF2K5VNTQZ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-26T05:52:20.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-compare-025e1792-obj-revived</Key>
    <VersionId>01KMMB6VQGNSCK9WTKN2GV5909</VersionId>
    <IsLatest>true</IsLatest>
    
... [truncated]
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
X-Amz-Date: 20260401T055958Z
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
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-e2c13c28%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T060003Z
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
  <Prefix>lov-test-e2c13c28/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-e2c13c28/obj-alive</Key>
    <VersionId>01KN3T16Y7Y19MJN9YNHK8TJYK</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:01.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e2c13c28/obj-alive</Key>
    <VersionId>01KN3T16AXSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T06:00:00.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-e2c13c28/obj-deleted</Key>
    <VersionId>01KN3T181MY19MJN9YNHK8TJYK</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:02.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-e2c13c28/obj-deleted</Key>
    <VersionId>01KN3T17HBSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T06:00:02.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e2c13c28/obj-revived</Key>
    <VersionId>01KN3T18V699A9CQQZ0Y995GYH</VersionId>
    <IsLatest>true</IsL
... [truncated]
```

---

### [PASS] test_alive_object_has_two_versions

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-e2c13c28%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T060004Z
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
  <Prefix>lov-test-e2c13c28/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-e2c13c28/obj-alive</Key>
    <VersionId>01KN3T16Y7Y19MJN9YNHK8TJYK</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:01.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e2c13c28/obj-alive</Key>
    <VersionId>01KN3T16AXSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T06:00:00.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-e2c13c28/obj-deleted</Key>
    <VersionId>01KN3T181MY19MJN9YNHK8TJYK</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:02.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-e2c13c28/obj-deleted</Key>
    <VersionId>01KN3T17HBSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T06:00:02.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e2c13c28/obj-revived</Key>
    <VersionId>01KN3T18V699A9CQQZ0Y995GYH</VersionId>
    <IsLatest>true</IsL
... [truncated]
```

---

### [PASS] test_deleted_object_has_delete_marker_as_latest

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-e2c13c28%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T060004Z
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
  <Prefix>lov-test-e2c13c28/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-e2c13c28/obj-alive</Key>
    <VersionId>01KN3T16Y7Y19MJN9YNHK8TJYK</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:01.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e2c13c28/obj-alive</Key>
    <VersionId>01KN3T16AXSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T06:00:00.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-e2c13c28/obj-deleted</Key>
    <VersionId>01KN3T181MY19MJN9YNHK8TJYK</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:02.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-e2c13c28/obj-deleted</Key>
    <VersionId>01KN3T17HBSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T06:00:02.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e2c13c28/obj-revived</Key>
    <VersionId>01KN3T18V699A9CQQZ0Y995GYH</VersionId>
    <IsLatest>true</IsL
... [truncated]
```

---

### [PASS] test_revived_object_has_version_as_latest

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-e2c13c28%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T060005Z
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
  <Prefix>lov-test-e2c13c28/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-e2c13c28/obj-alive</Key>
    <VersionId>01KN3T16Y7Y19MJN9YNHK8TJYK</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:01.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e2c13c28/obj-alive</Key>
    <VersionId>01KN3T16AXSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T06:00:00.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-e2c13c28/obj-deleted</Key>
    <VersionId>01KN3T181MY19MJN9YNHK8TJYK</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:02.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-e2c13c28/obj-deleted</Key>
    <VersionId>01KN3T17HBSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T06:00:02.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e2c13c28/obj-revived</Key>
    <VersionId>01KN3T18V699A9CQQZ0Y995GYH</VersionId>
    <IsLatest>true</IsL
... [truncated]
```

---

### [PASS] test_ordering_within_same_key

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-e2c13c28%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T060005Z
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
  <Prefix>lov-test-e2c13c28/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-e2c13c28/obj-alive</Key>
    <VersionId>01KN3T16Y7Y19MJN9YNHK8TJYK</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:01.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e2c13c28/obj-alive</Key>
    <VersionId>01KN3T16AXSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T06:00:00.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-e2c13c28/obj-deleted</Key>
    <VersionId>01KN3T181MY19MJN9YNHK8TJYK</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:02.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-e2c13c28/obj-deleted</Key>
    <VersionId>01KN3T17HBSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T06:00:02.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e2c13c28/obj-revived</Key>
    <VersionId>01KN3T18V699A9CQQZ0Y995GYH</VersionId>
    <IsLatest>true</IsL
... [truncated]
```

---

### [PASS] test_delete_marker_has_no_size_or_etag

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-e2c13c28%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T060006Z
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
  <Prefix>lov-test-e2c13c28/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-e2c13c28/obj-alive</Key>
    <VersionId>01KN3T16Y7Y19MJN9YNHK8TJYK</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:01.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e2c13c28/obj-alive</Key>
    <VersionId>01KN3T16AXSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T06:00:00.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-e2c13c28/obj-deleted</Key>
    <VersionId>01KN3T181MY19MJN9YNHK8TJYK</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:02.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <Version>
    <Key>lov-test-e2c13c28/obj-deleted</Key>
    <VersionId>01KN3T17HBSHQQRRNHC3QHGCTR</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-04-01T06:00:02.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-e2c13c28/obj-revived</Key>
    <VersionId>01KN3T18V699A9CQQZ0Y995GYH</VersionId>
    <IsLatest>true</IsL
... [truncated]
```

---

### [PASS] test_only_delete_markers_no_versions

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-dm-only-5c9b930d%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T060010Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 893
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-dm-only-5c9b930d/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-5c9b930d/dm-only-1</Key>
    <VersionId>01KN3T1EHWWGRF5MB12SCEBYMG</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:09.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>lov-dm-only-5c9b930d/dm-only-2</Key>
    <VersionId>01KN3T1FMBSZAT4XNNA517WX7E</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:10.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### [PASS] test_delete_markers_are_all_latest

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-dm-only-5c9b930d%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T060010Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 893
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-dm-only-5c9b930d/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-5c9b930d/dm-only-1</Key>
    <VersionId>01KN3T1EHWWGRF5MB12SCEBYMG</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:09.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>lov-dm-only-5c9b930d/dm-only-2</Key>
    <VersionId>01KN3T1FMBSZAT4XNNA517WX7E</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:10.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### [PASS] test_delete_markers_have_owner_and_version_id

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-dm-only-5c9b930d%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T060011Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 893
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-dm-only-5c9b930d/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-5c9b930d/dm-only-1</Key>
    <VersionId>01KN3T1EHWWGRF5MB12SCEBYMG</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:09.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
  <DeleteMarker>
    <Key>lov-dm-only-5c9b930d/dm-only-2</Key>
    <VersionId>01KN3T1FMBSZAT4XNNA517WX7E</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:10.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---

### [PASS] test_only_markers_with_max_keys_1

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=1&prefix=lov-dm-only-5c9b930d%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T060012Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: application/xml
Content-Length: 734
X-Amz-Bucket-Region: us-east-1
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-dagm-bucket-listversioning</Name>
  <Prefix>lov-dm-only-5c9b930d/</Prefix>
  <KeyMarker/>
  <VersionIdMarker/>
  <NextKeyMarker>lov-dm-only-5c9b930d/dm-only-1</NextKeyMarker>
  <NextVersionIdMarker>01KN3T1EHWWGRF5MB12SCEBYMG</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-5c9b930d/dm-only-1</Key>
    <VersionId>01KN3T1EHWWGRF5MB12SCEBYMG</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-04-01T06:00:09.000Z</LastModified>
    <Owner>
      <ID>0ea38b1b22584b3cc52c24f5232d4056ec09b15c94b45b3e67bee93845635ddf</ID>
    </Owner>
  </DeleteMarker>
</ListVersionsResult>

```

---
