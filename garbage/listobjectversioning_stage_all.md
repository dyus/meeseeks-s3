# S3 Compliance: All Tests

Generated: 2026-03-25 17:29:26

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
X-Amz-Date: 20260325T152759Z
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
  <RequestId>584fb33e763322eacfb7c6873e2c1ae9</RequestId>
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
X-Amz-Date: 20260325T152801Z
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
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>4eb7962e1e7459444d8bdc96d0e36afd</RequestId>
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
X-Amz-Date: 20260325T152801Z
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
  <ArgumentValue>invalid</ArgumentValue>
  <ArgumentName>encoding-type</ArgumentName>
  <RequestId>f51c0b44ba282f08c6626b4b4485948f</RequestId>
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
X-Amz-Date: 20260325T152803Z
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
X-Amz-Date: 20260325T152803Z
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
  <RequestId>741c694d7696c61e1a5d678e63756ab7</RequestId>
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
X-Amz-Date: 20260325T152804Z
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
  <RequestId>fafe21ac7a624463ae25044539a3f83d</RequestId>
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
X-Amz-Date: 20260325T152804Z
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
  <RequestId>087aab75997715991a04b7cc800e8241</RequestId>
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
X-Amz-Date: 20260325T152805Z
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
  <RequestId>b9d6f9086e85240b4ceafc7e3ca72fb3</RequestId>
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
X-Amz-Date: 20260325T152805Z
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
  <RequestId>89972304bcb57a4b3d9c78a47a38dc43</RequestId>
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
X-Amz-Date: 20260325T152806Z
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
  <RequestId>69f666fea814f548d5f1e15c727b6fd0</RequestId>
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
X-Amz-Date: 20260325T152807Z
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
  <RequestId>9fa53f2b054dc45f58e5ea5c91f405ef</RequestId>
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
X-Amz-Date: 20260325T152807Z
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
  <RequestId>f6cbbaa4e20e730d04032200d869bf53</RequestId>
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
X-Amz-Date: 20260325T152808Z
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
  <RequestId>1f9425c2ac645e5260c07a501744b14f</RequestId>
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
X-Amz-Date: 20260325T152808Z
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
  <RequestId>535fa0757eb8cac8a68137f680da46c7</RequestId>
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
X-Amz-Date: 20260325T152809Z
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
X-Amz-Date: 20260325T152809Z
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
  <RequestId>9dba40823b6bfc6d83c173c285af6ce2</RequestId>
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
X-Amz-Date: 20260325T152810Z
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
  <RequestId>cbe760b7777621f497634d08519652b1</RequestId>
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
X-Amz-Date: 20260325T152811Z
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
  <RequestId>f8b68f4d881e623791d6787b718b15fc</RequestId>
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
X-Amz-Date: 20260325T152811Z
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
  <RequestId>800cf56379b5c067e1b007a1a7662710</RequestId>
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
X-Amz-Date: 20260325T152812Z
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
  <RequestId>bd13f06cbc8b3c422c23cd38bf10355b</RequestId>
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
X-Amz-Date: 20260325T152812Z
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
  <RequestId>2f9756372bdfb72d04cea3e14faa6bb3</RequestId>
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
X-Amz-Date: 20260325T152813Z
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
  <ArgumentName>version-id-marker</ArgumentName>
  <ArgumentValue>bad-vid</ArgumentValue>
  <RequestId>bf85943b94e6b0e00359adca47dff98d</RequestId>
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
X-Amz-Date: 20260325T152813Z
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
  <RequestId>c0b00728b915ce46b7dc18cf2857a33c</RequestId>
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
X-Amz-Date: 20260325T152814Z
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
X-Amz-Date: 20260325T152815Z
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
  <RequestId>81328d77b9ff2973fe1f09738ad2af1c</RequestId>
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
X-Amz-Date: 20260325T152815Z
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
  <RequestId>040a703dad395e60cdb09c7d026f22b9</RequestId>
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
X-Amz-Date: 20260325T152816Z
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
  <RequestId>4d038f67172d2a1bd48764628f6b9cfa</RequestId>
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
X-Amz-Date: 20260325T152816Z
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
  <RequestId>29b108f1049a432cf8b540bcd93ab449</RequestId>
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
X-Amz-Date: 20260325T152817Z
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
  <RequestId>a942538982fe2352a0866018275b3e53</RequestId>
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
X-Amz-Date: 20260325T152817Z
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
  <RequestId>b396e82384dc5afcc765e97f4ae11fd1</RequestId>
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
X-Amz-Date: 20260325T152818Z
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
  <RequestId>5cb11c3917dc74f67e65b36e69a90c9f</RequestId>
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
X-Amz-Date: 20260325T152818Z
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
  <RequestId>07adc1cca37b0fda01de53caa6808daf</RequestId>
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
X-Amz-Date: 20260325T152819Z
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
  <RequestId>eef0cf1aac1ca67e7fb7596ee5174947</RequestId>
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
X-Amz-Date: 20260325T152819Z
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
  <RequestId>6137337f21011b1f64586bdbf2020122</RequestId>
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
X-Amz-Date: 20260325T152820Z
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
  <RequestId>823f664a7a77b7c1a416289b832afb05</RequestId>
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
X-Amz-Date: 20260325T152821Z
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
  <RequestId>4f2279758c4f4e467f141cd54f47af1d</RequestId>
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
X-Amz-Date: 20260325T152821Z
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
X-Amz-Date: 20260325T152822Z
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
X-Amz-Date: 20260325T152822Z
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
X-Amz-Date: 20260325T152823Z
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
X-Amz-Date: 20260325T152824Z
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
  <RequestId>c729d58e3f5a1ef99938c563ab7d38fe</RequestId>
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
X-Amz-Date: 20260325T152824Z
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
  <RequestId>fa51a8a30a4cd5ba1fb989f9358d74f5</RequestId>
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
X-Amz-Date: 20260325T152825Z
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
  <RequestId>9b214f9f359d685be143a177382e1a92</RequestId>
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
X-Amz-Date: 20260325T152826Z
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
X-Amz-Date: 20260325T152827Z
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
X-Amz-Date: 20260325T152828Z
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
X-Amz-Date: 20260325T152829Z
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
  <RequestId>e641433c0f085c36fd52c7d19070bbd8</RequestId>
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
X-Amz-Date: 20260325T152829Z
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
  <ArgumentValue>ðŸ”‘</ArgumentValue>
  <RequestId>13daae33d28e6f0a80bf01f3ac21b40a</RequestId>
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
X-Amz-Date: 20260325T152830Z
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
  <RequestId>76b5f9028ac88a5b84eb3be7a819fb6f</RequestId>
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
X-Amz-Date: 20260325T152831Z
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
  <RequestId>6fbc048866a0785798cfc9feac736888</RequestId>
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
X-Amz-Date: 20260325T152831Z
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
  <RequestId>6b1e69180aeb2a8ec00073ffd9a1c543</RequestId>
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
X-Amz-Date: 20260325T152832Z
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
  <RequestId>cd95a25fdcadc4b6b36e105ca7064840</RequestId>
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
X-Amz-Date: 20260325T152832Z
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
  <RequestId>05aa9393e524c44cb07cd722e7e5bf5b</RequestId>
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
X-Amz-Date: 20260325T152833Z
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
  <RequestId>6905bad6a74d952fb0a5d6e1ad0d0f7e</RequestId>
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
X-Amz-Date: 20260325T152834Z
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
  <RequestId>2377b97c9ee9d6837d330c5d64b73f57</RequestId>
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
X-Amz-Date: 20260325T152834Z
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
  <RequestId>7170531fc2dd7993dd6be2ff4572d3d5</RequestId>
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
X-Amz-Date: 20260325T152835Z
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
  <RequestId>731998132f104781522c61006162bef5</RequestId>
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
X-Amz-Date: 20260325T152836Z
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
  <RequestId>8c9619788feda385553f92b71ae0bb3f</RequestId>
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
X-Amz-Date: 20260325T152836Z
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
  <RequestId>fcc75a8c5c248a2f2caf7cb8d093e412</RequestId>
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
X-Amz-Date: 20260325T152837Z
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
  <RequestId>f09def3148d868c252b253a28da62a32</RequestId>
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
X-Amz-Date: 20260325T152837Z
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
  <RequestId>fcbde9e2acc507700fe8191431e6ff7e</RequestId>
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
X-Amz-Date: 20260325T152838Z
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
  <RequestId>dd77a748b963147fd71a05d99ede710d</RequestId>
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
X-Amz-Date: 20260325T152838Z
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
X-Amz-Date: 20260325T152839Z
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
  <RequestId>6b5cedcc46b47ef50c05c2dcda388996</RequestId>
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
X-Amz-Date: 20260325T152839Z
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
  <RequestId>1ca68026f8946d39830a9426e1634294</RequestId>
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
X-Amz-Date: 20260325T152840Z
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
  <RequestId>be17a91239233a9338527c5aa0f02420</RequestId>
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
X-Amz-Date: 20260325T152840Z
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
  <RequestId>450a57b8b90b033fb55975ecbd0cd20c</RequestId>
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
X-Amz-Date: 20260325T152841Z
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
  <RequestId>e6e7f87321513017f86234bf5dde451b</RequestId>
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
X-Amz-Date: 20260325T152841Z
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
  <RequestId>66e8ee1a0359e3c8a19caf4a09947dfa</RequestId>
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
X-Amz-Date: 20260325T152842Z
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
  <RequestId>8017eb59fdf36c84ef01c2150cf89192</RequestId>
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
X-Amz-Date: 20260325T152842Z
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
  <RequestId>4078631114df925465df952b5ced1aff</RequestId>
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
X-Amz-Date: 20260325T152842Z
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
  <RequestId>23ef69e9bab45acca871969b4aa987f3</RequestId>
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
X-Amz-Date: 20260325T152843Z
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
  <RequestId>ffcc40b503e461093423c6ceee6048f9</RequestId>
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
X-Amz-Date: 20260325T152843Z
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
  <RequestId>38f3a6fce9deae4e3098f349a459bcd7</RequestId>
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
X-Amz-Date: 20260325T152844Z
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
  <RequestId>6185e38ba27734f5b89f126c46a3b385</RequestId>
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
X-Amz-Date: 20260325T152844Z
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
X-Amz-Date: 20260325T152845Z
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
  <RequestId>ea690e54b1bf663affc6517f1a77e8a0</RequestId>
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
X-Amz-Date: 20260325T152846Z
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
X-Amz-Date: 20260325T152846Z
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
  <RequestId>b336717d49b422beb5251e918f9688d3</RequestId>
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
X-Amz-Date: 20260325T152847Z
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
  <RequestId>f585cf388b12628daea191ffd9a52542</RequestId>
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
X-Amz-Date: 20260325T152847Z
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
X-Amz-Date: 20260325T152848Z
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
X-Amz-Date: 20260325T152848Z
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
X-Amz-Date: 20260325T152849Z
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
X-Amz-Date: 20260325T152849Z
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
  <ArgumentValue/>
  <ArgumentName>encoding-type</ArgumentName>
  <RequestId>d141b0477365dfaf513af4dd8bc9e73c</RequestId>
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
X-Amz-Date: 20260325T152850Z
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
X-Amz-Date: 20260325T152850Z
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
  <RequestId>0b3253f3ddc7c0ff51c110f9a36de81d</RequestId>
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
X-Amz-Date: 20260325T152851Z
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
  <RequestId>c9d785509e2a9c42cc80e4afdfdfe62b</RequestId>
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
X-Amz-Date: 20260325T152851Z
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
  <RequestId>d0534507703d77ddfe4ac5a51991b03a</RequestId>
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
X-Amz-Date: 20260325T152852Z
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
  <RequestId>09a11b2c893c314ca2775d5eaf5c79ae</RequestId>
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
X-Amz-Date: 20260325T152852Z
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
X-Amz-Date: 20260325T152853Z
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
X-Amz-Date: 20260325T152854Z
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
X-Amz-Date: 20260325T152854Z
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
X-Amz-Date: 20260325T152855Z
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
X-Amz-Date: 20260325T152857Z
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
X-Amz-Date: 20260325T152857Z
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
X-Amz-Date: 20260325T152858Z
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
X-Amz-Date: 20260325T152859Z
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
X-Amz-Date: 20260325T152859Z
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
X-Amz-Date: 20260325T152900Z
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
X-Amz-Date: 20260325T152900Z
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
X-Amz-Date: 20260325T152901Z
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
X-Amz-Date: 20260325T152901Z
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
X-Amz-Date: 20260325T152902Z
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
X-Amz-Date: 20260325T152902Z
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
X-Amz-Date: 20260325T152903Z
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
X-Amz-Date: 20260325T152903Z
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
X-Amz-Date: 20260325T152904Z
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
X-Amz-Date: 20260325T152905Z
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
X-Amz-Date: 20260325T152905Z
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
X-Amz-Date: 20260325T152906Z
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
X-Amz-Date: 20260325T152906Z
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
X-Amz-Date: 20260325T152908Z
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
X-Amz-Date: 20260325T152908Z
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
X-Amz-Date: 20260325T152909Z
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
X-Amz-Date: 20260325T152910Z
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
X-Amz-Date: 20260325T152911Z
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
X-Amz-Date: 20260325T152911Z
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
X-Amz-Date: 20260325T152912Z
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
X-Amz-Date: 20260325T152912Z
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
X-Amz-Date: 20260325T152913Z
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
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-780628b3%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260325T152916Z
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
  <Prefix>lov-test-780628b3/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-780628b3/obj-alive</Key>
    <VersionId>01KMJSTF0BNQ028CBY4E6NJMSN</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:14.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-alive</Key>
    <VersionId>01KMJSTEG1NQ028CBY4E6NJMSN</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:14.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-deleted</Key>
    <VersionId>01KMJSTFBANQ028CBY4E6NJMSN</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-revived</Key>
    <VersionId>01KMJSTGK92YF83NCKKY4TB4E1</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:16.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-revived</Key>
    <VersionId>01KMJSTFX2E38Z14B4537VP1QQ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-780628b3/obj-deleted</Key>
    <VersionId>01KMJSTFSNE38Z14B4537VP1QQ</VersionId>
    <IsL
... [truncated]
```

---

### [PASS] test_alive_object_has_two_versions

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-780628b3%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260325T152917Z
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
  <Prefix>lov-test-780628b3/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-780628b3/obj-alive</Key>
    <VersionId>01KMJSTF0BNQ028CBY4E6NJMSN</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:14.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-alive</Key>
    <VersionId>01KMJSTEG1NQ028CBY4E6NJMSN</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:14.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-deleted</Key>
    <VersionId>01KMJSTFBANQ028CBY4E6NJMSN</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-revived</Key>
    <VersionId>01KMJSTGK92YF83NCKKY4TB4E1</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:16.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-revived</Key>
    <VersionId>01KMJSTFX2E38Z14B4537VP1QQ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-780628b3/obj-deleted</Key>
    <VersionId>01KMJSTFSNE38Z14B4537VP1QQ</VersionId>
    <IsL
... [truncated]
```

---

### [PASS] test_deleted_object_has_delete_marker_as_latest

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-780628b3%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260325T152917Z
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
  <Prefix>lov-test-780628b3/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-780628b3/obj-alive</Key>
    <VersionId>01KMJSTF0BNQ028CBY4E6NJMSN</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:14.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-alive</Key>
    <VersionId>01KMJSTEG1NQ028CBY4E6NJMSN</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:14.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-deleted</Key>
    <VersionId>01KMJSTFBANQ028CBY4E6NJMSN</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-revived</Key>
    <VersionId>01KMJSTGK92YF83NCKKY4TB4E1</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:16.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-revived</Key>
    <VersionId>01KMJSTFX2E38Z14B4537VP1QQ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-780628b3/obj-deleted</Key>
    <VersionId>01KMJSTFSNE38Z14B4537VP1QQ</VersionId>
    <IsL
... [truncated]
```

---

### [PASS] test_revived_object_has_version_as_latest

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-780628b3%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260325T152918Z
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
  <Prefix>lov-test-780628b3/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-780628b3/obj-alive</Key>
    <VersionId>01KMJSTF0BNQ028CBY4E6NJMSN</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:14.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-alive</Key>
    <VersionId>01KMJSTEG1NQ028CBY4E6NJMSN</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:14.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-deleted</Key>
    <VersionId>01KMJSTFBANQ028CBY4E6NJMSN</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-revived</Key>
    <VersionId>01KMJSTGK92YF83NCKKY4TB4E1</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:16.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-revived</Key>
    <VersionId>01KMJSTFX2E38Z14B4537VP1QQ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-780628b3/obj-deleted</Key>
    <VersionId>01KMJSTFSNE38Z14B4537VP1QQ</VersionId>
    <IsL
... [truncated]
```

---

### [FAIL] test_ordering_within_same_key

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-780628b3%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260325T152918Z
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
  <Prefix>lov-test-780628b3/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-780628b3/obj-alive</Key>
    <VersionId>01KMJSTF0BNQ028CBY4E6NJMSN</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:14.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-alive</Key>
    <VersionId>01KMJSTEG1NQ028CBY4E6NJMSN</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:14.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-deleted</Key>
    <VersionId>01KMJSTFBANQ028CBY4E6NJMSN</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-revived</Key>
    <VersionId>01KMJSTGK92YF83NCKKY4TB4E1</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:16.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-revived</Key>
    <VersionId>01KMJSTFX2E38Z14B4537VP1QQ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-780628b3/obj-deleted</Key>
    <VersionId>01KMJSTFSNE38Z14B4537VP1QQ</VersionId>
    <IsL
... [truncated]
```

---

### [PASS] test_delete_marker_has_no_size_or_etag

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-test-780628b3%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260325T152919Z
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
  <Prefix>lov-test-780628b3/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Version>
    <Key>lov-test-780628b3/obj-alive</Key>
    <VersionId>01KMJSTF0BNQ028CBY4E6NJMSN</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:14.000Z</LastModified>
    <ETag>"1b267619c4812cc46ee281747884ca50"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-alive</Key>
    <VersionId>01KMJSTEG1NQ028CBY4E6NJMSN</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:14.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-deleted</Key>
    <VersionId>01KMJSTFBANQ028CBY4E6NJMSN</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-revived</Key>
    <VersionId>01KMJSTGK92YF83NCKKY4TB4E1</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:16.000Z</LastModified>
    <ETag>"29b3eca3be7e4788a6e777518e6957ce"</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <Version>
    <Key>lov-test-780628b3/obj-revived</Key>
    <VersionId>01KMJSTFX2E38Z14B4537VP1QQ</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-03-25T15:29:15.000Z</LastModified>
    <ETag>"6654c734ccab8f440ff0825eb443dc7f"</ETag>
    <Size>2</Size>
    <StorageClass>STANDARD</StorageClass>
  </Version>
  <DeleteMarker>
    <Key>lov-test-780628b3/obj-deleted</Key>
    <VersionId>01KMJSTFSNE38Z14B4537VP1QQ</VersionId>
    <IsL
... [truncated]
```

---

### [PASS] test_only_delete_markers_no_versions

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-dm-only-c1ff2e0a%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260325T152921Z
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
  <Prefix>lov-dm-only-c1ff2e0a/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-c1ff2e0a/dm-only-1</Key>
    <VersionId>01KMJSTMPJ2YF83NCKKY4TB4E1</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:20.000Z</LastModified>
  </DeleteMarker>
  <DeleteMarker>
    <Key>lov-dm-only-c1ff2e0a/dm-only-2</Key>
    <VersionId>01KMJSTNFYBHA8SGNM12SYJQ6E</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:21.000Z</LastModified>
  </DeleteMarker>
</ListVersionsResult>

```

---

### [PASS] test_delete_markers_are_all_latest

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-dm-only-c1ff2e0a%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260325T152922Z
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
  <Prefix>lov-dm-only-c1ff2e0a/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-c1ff2e0a/dm-only-1</Key>
    <VersionId>01KMJSTMPJ2YF83NCKKY4TB4E1</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:20.000Z</LastModified>
  </DeleteMarker>
  <DeleteMarker>
    <Key>lov-dm-only-c1ff2e0a/dm-only-2</Key>
    <VersionId>01KMJSTNFYBHA8SGNM12SYJQ6E</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:21.000Z</LastModified>
  </DeleteMarker>
</ListVersionsResult>

```

---

### [FAIL] test_delete_markers_have_owner_and_version_id

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&prefix=lov-dm-only-c1ff2e0a%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260325T152922Z
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
  <Prefix>lov-dm-only-c1ff2e0a/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-c1ff2e0a/dm-only-1</Key>
    <VersionId>01KMJSTMPJ2YF83NCKKY4TB4E1</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:20.000Z</LastModified>
  </DeleteMarker>
  <DeleteMarker>
    <Key>lov-dm-only-c1ff2e0a/dm-only-2</Key>
    <VersionId>01KMJSTNFYBHA8SGNM12SYJQ6E</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:21.000Z</LastModified>
  </DeleteMarker>
</ListVersionsResult>

```

---

### [PASS] test_only_markers_with_max_keys_1

**Markers:** `s3_handler`, `list_object_versions`

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versions&max-keys=1&prefix=lov-dm-only-c1ff2e0a%2F HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260325T152923Z
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
  <Prefix>lov-dm-only-c1ff2e0a/</Prefix>
  <KeyMarker/>
  <VersionIDMarker/>
  <NextKeyMarker>lov-dm-only-c1ff2e0a/dm-only-1</NextKeyMarker>
  <NextVersionIdMarker>01KMJSTMPJ2YF83NCKKY4TB4E1</NextVersionIdMarker>
  <MaxKeys>1</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <DeleteMarker>
    <Key>lov-dm-only-c1ff2e0a/dm-only-1</Key>
    <VersionId>01KMJSTMPJ2YF83NCKKY4TB4E1</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-03-25T15:29:20.000Z</LastModified>
  </DeleteMarker>
</ListVersionsResult>

```

---
