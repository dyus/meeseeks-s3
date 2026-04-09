# S3 Compliance: GetObject

Generated: 2026-04-01 08:16:16

## Summary

| Metric | Count |
|--------|-------|
| Total | 24 |
| Passed | 24 |
| Failed | 0 |
| Skipped | 0 |

## Contents

- [GetObject](#getobject) (24 tests)

---

## GetObject

### [PASS] test_1_1_get_without_version_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T061408Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t1-1-44107c5b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 5
x-amz-content-sha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
X-Amz-Date: 20260401T061409Z
Authorization: [REDACTED]

hello
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "5d41402abc4b2a76b9719d911017c592"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t1-1-44107c5b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061411Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 5
Accept-Ranges: bytes
Etag: "5d41402abc4b2a76b9719d911017c592"
Last-Modified: Wed, 01 Apr 2026 06:14:11 GMT
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

hello
```

---

### [PASS] test_1_2_get_version_id_null

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T061412Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t1-2-fb75a959 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 10
x-amz-content-sha256: 03e687cdbfd7a4dd3cc81f2e71e33cbc52d6200e8cdd487a97153daff1421bc9
X-Amz-Date: 20260401T061413Z
Authorization: [REDACTED]

hello-null
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "1446cb0f43b42cf6280efed5e46fcdc7"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t1-2-fb75a959?versionId=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061414Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 10
Accept-Ranges: bytes
Etag: "1446cb0f43b42cf6280efed5e46fcdc7"
Last-Modified: Wed, 01 Apr 2026 06:14:14 GMT
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

hello-null
```

---

### [PASS] test_1_3_get_nonexistent_version_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T061415Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t1-3-448d8530 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 5
x-amz-content-sha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
X-Amz-Date: 20260401T061416Z
Authorization: [REDACTED]

hello
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "5d41402abc4b2a76b9719d911017c592"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t1-3-448d8530?versionId=nonexistent-version-id-12345 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061417Z
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
  <RequestId>64639f766a82960858639464a40cff5f</RequestId>
</Error>

```

---

### [PASS] test_1_4_get_empty_version_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T061418Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t1-4-9b706a47 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 5
x-amz-content-sha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
X-Amz-Date: 20260401T061419Z
Authorization: [REDACTED]

hello
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "5d41402abc4b2a76b9719d911017c592"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t1-4-9b706a47?versionId= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061420Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 262
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue/>
  <RequestId>b3a9c009c66d9c85dd35d07f0bfb40a5</RequestId>
</Error>

```

---

### [PASS] test_1_5_get_version_id_no_value

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T061424Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t1-5-cc5a5ff6 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 5
x-amz-content-sha256: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
X-Amz-Date: 20260401T061424Z
Authorization: [REDACTED]

hello
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "5d41402abc4b2a76b9719d911017c592"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t1-5-cc5a5ff6?versionId HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061425Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 262
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentValue/>
  <ArgumentName>versionId</ArgumentName>
  <RequestId>cfe86a3a2e554168c154c19a7b7b1c18</RequestId>
</Error>

```

---

### [PASS] test_2_1_get_latest_without_version_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061426Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-1-c5a95ae3 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: fc6af3ec64d3d71d0919a48ee6efa31d75ae83e56147079c8a117fb2fb15a507
X-Amz-Date: 20260401T061427Z
Authorization: [REDACTED]

version1
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "966634ebf2fc135707d6753692bf4b1e"
X-Amz-Version-Id: 01KN3TVNJYSZAT4XNNA517WX7E
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-1-c5a95ae3 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: 366a963b60fd5ee4bb17a3e7cd62c92277357c3cd7a443ffc42808351afbe7e2
X-Amz-Date: 20260401T061428Z
Authorization: [REDACTED]

version2
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "2e0e95285f08a07dea17e7ee111b21c8"
X-Amz-Version-Id: 01KN3TVPRK7Y1TSEHH97Z8S3E9
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-1-c5a95ae3 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061429Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 8
Accept-Ranges: bytes
Etag: "2e0e95285f08a07dea17e7ee111b21c8"
Last-Modified: Wed, 01 Apr 2026 06:14:29 GMT
X-Amz-Version-Id: 01KN3TVPRK7Y1TSEHH97Z8S3E9
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

version2
```

---

### [PASS] test_2_2_get_specific_version_v1

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061430Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-2-c5f4bee9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: fc6af3ec64d3d71d0919a48ee6efa31d75ae83e56147079c8a117fb2fb15a507
X-Amz-Date: 20260401T061432Z
Authorization: [REDACTED]

version1
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "966634ebf2fc135707d6753692bf4b1e"
X-Amz-Version-Id: 01KN3TVTFM8P47R34QGK3TAN18
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-2-c5f4bee9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: 366a963b60fd5ee4bb17a3e7cd62c92277357c3cd7a443ffc42808351afbe7e2
X-Amz-Date: 20260401T061433Z
Authorization: [REDACTED]

version2
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "2e0e95285f08a07dea17e7ee111b21c8"
X-Amz-Version-Id: 01KN3TVVYYWGRF5MB12SCEBYMG
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-2-c5f4bee9?versionId=01KN3TVTFM8P47R34QGK3TAN18 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061435Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 8
Accept-Ranges: bytes
Etag: "966634ebf2fc135707d6753692bf4b1e"
Last-Modified: Wed, 01 Apr 2026 06:14:33 GMT
X-Amz-Version-Id: 01KN3TVTFM8P47R34QGK3TAN18
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

version1
```

---

### [PASS] test_2_3_get_specific_version_v2_latest

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061436Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-3-8d43c802 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: fc6af3ec64d3d71d0919a48ee6efa31d75ae83e56147079c8a117fb2fb15a507
X-Amz-Date: 20260401T061437Z
Authorization: [REDACTED]

version1
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "966634ebf2fc135707d6753692bf4b1e"
X-Amz-Version-Id: 01KN3TVZF8SZAT4XNNA517WX7E
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-3-8d43c802 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: 366a963b60fd5ee4bb17a3e7cd62c92277357c3cd7a443ffc42808351afbe7e2
X-Amz-Date: 20260401T061438Z
Authorization: [REDACTED]

version2
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "2e0e95285f08a07dea17e7ee111b21c8"
X-Amz-Version-Id: 01KN3TW09Y7Y1TSEHH97Z8S3E9
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-3-8d43c802?versionId=01KN3TW09Y7Y1TSEHH97Z8S3E9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061439Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 8
Accept-Ranges: bytes
Etag: "2e0e95285f08a07dea17e7ee111b21c8"
Last-Modified: Wed, 01 Apr 2026 06:14:39 GMT
X-Amz-Version-Id: 01KN3TW09Y7Y1TSEHH97Z8S3E9
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

version2
```

---

### [PASS] test_2_4_get_version_id_null_no_null_version

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061441Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-4-763f9db4 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 9
x-amz-content-sha256: 8098a1d643564bcccd6490cb701d4581e5761728ad4b356a4f4c5e00d60d0d2b
X-Amz-Date: 20260401T061441Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "c9987075e741e0f495fbba8b2159d92b"
X-Amz-Version-Id: 01KN3TW3HQ8P47R34QGK3TAN18
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-4-763f9db4?versionId=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061442Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Content-Length: 242
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>NoSuchVersion</Code>
  <Message>The specified version does not exist.</Message>
  <Key>t2-4-763f9db4</Key>
  <VersionId>null</VersionId>
  <RequestId>43e2c38550dcd8c88c167a1eb9ac0dab</RequestId>
</Error>

```

---

### [PASS] test_2_4a_get_empty_version_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061444Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-4a-b2247b36 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 9
x-amz-content-sha256: 8098a1d643564bcccd6490cb701d4581e5761728ad4b356a4f4c5e00d60d0d2b
X-Amz-Date: 20260401T061445Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "c9987075e741e0f495fbba8b2159d92b"
X-Amz-Version-Id: 01KN3TW6VRV9A2Y2ZQ3WB58XG2
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-4a-b2247b36?versionId= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061446Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 262
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue/>
  <RequestId>95ec4ae6b35a7be2cd7c9ec8c91388ce</RequestId>
</Error>

```

---

### [PASS] test_2_4b_get_version_id_no_value

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061447Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-4b-e1398832 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 9
x-amz-content-sha256: 8098a1d643564bcccd6490cb701d4581e5761728ad4b356a4f4c5e00d60d0d2b
X-Amz-Date: 20260401T061448Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "c9987075e741e0f495fbba8b2159d92b"
X-Amz-Version-Id: 01KN3TWABQ8R708H8M4FDDZ3WP
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-4b-e1398832?versionId HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061449Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 262
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue/>
  <RequestId>620d55be8358e377e80f384a639e7644</RequestId>
</Error>

```

---

### [PASS] test_2_5_get_latest_delete_marker

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061450Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-5-0a7460dd HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 13
x-amz-content-sha256: 9e07f73f258938f25320f6415f98b960d1642d079b7dd85a811d3e415922dd95
X-Amz-Date: 20260401T061451Z
Authorization: [REDACTED]

to-be-deleted
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "4c5ac2465788ee2ad44c5dc28f6a47b4"
X-Amz-Version-Id: 01KN3TWCQ250SFAH3SGYQER416
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-5-0a7460dd HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061453Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TWEJ0V9A2Y2ZQ3WB58XG2
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-5-0a7460dd HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061454Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Content-Length: 183
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TWEJ0V9A2Y2ZQ3WB58XG2
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <RequestId>a98fae915c360f85c155ddf97b9b340d</RequestId>
</Error>

```

---

### [PASS] test_2_6_get_version_id_of_delete_marker

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061454Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-6-2c0cbc3b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 13
x-amz-content-sha256: 9e07f73f258938f25320f6415f98b960d1642d079b7dd85a811d3e415922dd95
X-Amz-Date: 20260401T061455Z
Authorization: [REDACTED]

to-be-deleted
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "4c5ac2465788ee2ad44c5dc28f6a47b4"
X-Amz-Version-Id: 01KN3TWGZ68R708H8M4FDDZ3WP
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-6-2c0cbc3b HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061456Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TWHSG7Y1TSEHH97Z8S3E9
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-6-2c0cbc3b?versionId=01KN3TWHSG7Y1TSEHH97Z8S3E9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061457Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 405
Content-Type: application/xml
Content-Length: 215
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TWHSG7Y1TSEHH97Z8S3E9
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>MethodNotAllowed</Code>
  <Message>The specified method is not allowed against this resource.</Message>
  <RequestId>88527db9c22ab44070ef0786676b3d70</RequestId>
</Error>

```

---

### [PASS] test_2_7_get_version_before_delete_marker

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061458Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-7-b2c722fc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: 0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5
X-Amz-Date: 20260401T061459Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "919c8b643b7133116b02fc0d9bb7df3f"
X-Amz-Version-Id: 01KN3TWMEQ8P47R34QGK3TAN18
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-7-b2c722fc HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061500Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TWN7GAW1ZB3C1STPTATYG
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-7-b2c722fc?versionId=01KN3TWMEQ8P47R34QGK3TAN18 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061500Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 8
Accept-Ranges: bytes
Etag: "919c8b643b7133116b02fc0d9bb7df3f"
Last-Modified: Wed, 01 Apr 2026 06:14:59 GMT
X-Amz-Version-Id: 01KN3TWMEQ8P47R34QGK3TAN18
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

original
```

---

### [PASS] test_2_8_get_latest_after_revive

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061501Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-8-cb018c45 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: 0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5
X-Amz-Date: 20260401T061502Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "919c8b643b7133116b02fc0d9bb7df3f"
X-Amz-Version-Id: 01KN3TWQQDJ56CX9SK9YB64GPV
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-8-cb018c45 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061503Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TWRNK50SFAH3SGYQER416
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-8-cb018c45 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 7
x-amz-content-sha256: eb1c7f738bbe6d0fd106bf4a2fe976009eaeadaa7b25ce2fc8026197934d0cb9
X-Amz-Date: 20260401T061504Z
Authorization: [REDACTED]

revived
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "85501e7a9ff62c46459e4b900bfb34a6"
X-Amz-Version-Id: 01KN3TWVHEV9A2Y2ZQ3WB58XG2
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-8-cb018c45 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061507Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 7
Accept-Ranges: bytes
Etag: "85501e7a9ff62c46459e4b900bfb34a6"
Last-Modified: Wed, 01 Apr 2026 06:15:07 GMT
X-Amz-Version-Id: 01KN3TWVHEV9A2Y2ZQ3WB58XG2
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

revived
```

---

### [PASS] test_2_9_get_version_id_of_non_latest_delete_marker

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061508Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-9-e8ede105 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 8
x-amz-content-sha256: 0682c5f2076f099c34cfdd15a9e063849ed437a49677e6fcc5b4198c76575be5
X-Amz-Date: 20260401T061509Z
Authorization: [REDACTED]

original
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "919c8b643b7133116b02fc0d9bb7df3f"
X-Amz-Version-Id: 01KN3TWZJS8R708H8M4FDDZ3WP
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-9-e8ede105 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061511Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TX0NKGHTGYDSATQJM27G7
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-9-e8ede105 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 7
x-amz-content-sha256: eb1c7f738bbe6d0fd106bf4a2fe976009eaeadaa7b25ce2fc8026197934d0cb9
X-Amz-Date: 20260401T061512Z
Authorization: [REDACTED]

revived
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "85501e7a9ff62c46459e4b900bfb34a6"
X-Amz-Version-Id: 01KN3TX1QNAW1ZB3C1STPTATYG
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t2-9-e8ede105?versionId=01KN3TX0NKGHTGYDSATQJM27G7 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061514Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 405
Content-Type: application/xml
Content-Length: 215
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TX0NKGHTGYDSATQJM27G7
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>MethodNotAllowed</Code>
  <Message>The specified method is not allowed against this resource.</Message>
  <RequestId>b26bd805283b10a214994f4d030b1d8c</RequestId>
</Error>

```

---

### [PASS] test_3_1_get_without_version_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061515Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-1-e0b9698a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 9
x-amz-content-sha256: 8098a1d643564bcccd6490cb701d4581e5761728ad4b356a4f4c5e00d60d0d2b
X-Amz-Date: 20260401T061516Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "c9987075e741e0f495fbba8b2159d92b"
X-Amz-Version-Id: 01KN3TX58FJ56CX9SK9YB64GPV
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T061517Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-1-e0b9698a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 15
x-amz-content-sha256: 4d5bef27495627db85a60e7ced59988c275f36c10a2ca7e187bf60f5408dc1e3
X-Amz-Date: 20260401T061518Z
Authorization: [REDACTED]

suspended-write
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "c4a67bf2e43decab510dbfc83e3906d1"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-1-e0b9698a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061519Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 15
Accept-Ranges: bytes
Etag: "c4a67bf2e43decab510dbfc83e3906d1"
Last-Modified: Wed, 01 Apr 2026 06:15:19 GMT
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

suspended-write
```

---

### [PASS] test_3_2_get_version_id_null

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061531Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-2-4c602b10 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 9
x-amz-content-sha256: 8098a1d643564bcccd6490cb701d4581e5761728ad4b356a4f4c5e00d60d0d2b
X-Amz-Date: 20260401T061532Z
Authorization: [REDACTED]

versioned
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "c9987075e741e0f495fbba8b2159d92b"
X-Amz-Version-Id: 01KN3TXN24BZ577Y4BFZK9H2BQ
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T061533Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-2-4c602b10 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 12
x-amz-content-sha256: ad2404f43facdb2acc5f522834c49a758f5d5da69ea8efc430398b0b8907bdac
X-Amz-Date: 20260401T061535Z
Authorization: [REDACTED]

null-version
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8cc0972b3440a1f75dd1d5c3867e30c8"
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-2-4c602b10?versionId=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061536Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 12
Accept-Ranges: bytes
Etag: "8cc0972b3440a1f75dd1d5c3867e30c8"
Last-Modified: Wed, 01 Apr 2026 06:15:36 GMT
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

null-version
```

---

### [PASS] test_3_3_get_old_versioned_id

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061537Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-3-2c3a9a5e HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 10
x-amz-content-sha256: 192cbc1156a1cb47e362374b013d45d9cc2de8e711a31951f4fc5b374f40e0da
X-Amz-Date: 20260401T061538Z
Authorization: [REDACTED]

v1-enabled
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "3f03451103efdfe0b0d7e021ec65a84e"
X-Amz-Version-Id: 01KN3TXTS250SFAH3SGYQER416
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T061539Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-3-2c3a9a5e?versionId=01KN3TXTS250SFAH3SGYQER416 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061540Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 200
Content-Type: binary/octet-stream
Content-Length: 10
Accept-Ranges: bytes
Etag: "3f03451103efdfe0b0d7e021ec65a84e"
Last-Modified: Wed, 01 Apr 2026 06:15:39 GMT
X-Amz-Version-Id: 01KN3TXTS250SFAH3SGYQER416
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

v1-enabled
```

---

### [PASS] test_3_3a_get_empty_version_id_suspended

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061542Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-3a-c17889e9 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T061544Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3TY0FKCR0FDY1VPV8HZWCB
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T061545Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-3a-c17889e9?versionId= HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061547Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 262
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentValue/>
  <ArgumentName>versionId</ArgumentName>
  <RequestId>5764164373ea3f44338f3c012fd99149</RequestId>
</Error>

```

---

### [PASS] test_3_3b_get_version_id_no_value_suspended

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061549Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-3b-dddffe23 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T061550Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3TY637GHTGYDSATQJM27G7
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T061550Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-3b-dddffe23?versionId HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061552Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 400
Content-Type: application/xml
Content-Length: 262
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>InvalidArgument</Code>
  <Message>Version id cannot be the empty string</Message>
  <ArgumentName>versionId</ArgumentName>
  <ArgumentValue/>
  <RequestId>dd240986c0552bc1f1f8993dfe2a10df</RequestId>
</Error>

```

---

### [PASS] test_3_4_get_latest_delete_marker_suspended

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061554Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-4-769d5f3a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T061554Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3TYB38AW1ZB3C1STPTATYG
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T061556Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-4-769d5f3a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061557Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-4-769d5f3a HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061558Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Content-Length: 183
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <RequestId>3e2a8ada5d33826f8e40cc2f1566cb06</RequestId>
</Error>

```

---

### [PASS] test_3_5_get_version_id_null_delete_marker_suspended

**Markers:** `usefixtures`, `s3_handler`, `get_object_versioning`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061559Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-5-45214668 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T061600Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3TYGVHBZ577Y4BFZK9H2BQ
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 156
x-amz-content-sha256: 3a9142e9821132e5b05c9ff17a3336d43916126ddf86765eb6bb4ec5a0571d2f
X-Amz-Date: 20260401T061602Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Suspended</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-5-45214668 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061603Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 5

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/t3-5-45214668?versionId=null HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061605Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 405
Content-Type: application/xml
Content-Length: 215
X-Amz-Delete-Marker: true
X-Amz-Version-Id: null
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>MethodNotAllowed</Code>
  <Message>The specified method is not allowed against this resource.</Message>
  <RequestId>040d1e300760ae679b72de1f63c496d1</RequestId>
</Error>

```

---

### [PASS] test_compare_get_head_on_delete_marker

**Markers:** `usefixtures`, `s3_handler`

#### Request 1

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning?versioning HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/xml
X-Forwarded-Proto: https
Content-Length: 154
x-amz-content-sha256: 818762be52126f1b574554b80bc42554cf4ca626f6850c820ec437f5bf5c24a4
X-Amz-Date: 20260401T061606Z
Authorization: [REDACTED]

<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
  <MfaDelete>Disabled</MfaDelete>
</VersioningConfiguration>

```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 2

**Request:**

```http
PUT https://s3.stage.rabata.io/test-dagm-bucket-listversioning/dm-compare-5c00a921 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 4
x-amz-content-sha256: 3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7
X-Amz-Date: 20260401T061608Z
Authorization: [REDACTED]

data
```

**Response:**

```http
HTTP/1.1 200
Content-Length: 0
Etag: "8d777f385d3dfec8815d20f7496026dc"
X-Amz-Version-Id: 01KN3TYR8Q7MEC6N7BKV6CT1ZY
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 3

**Request:**

```http
DELETE https://s3.stage.rabata.io/test-dagm-bucket-listversioning/dm-compare-5c00a921 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061609Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 204
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TYSQ8CR0FDY1VPV8HZWCB
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 4

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/dm-compare-5c00a921 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061611Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
Content-Length: 183
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TYSQ8CR0FDY1VPV8HZWCB
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <RequestId>593d4e40c595e31d9d4ffdfbb4f02a41</RequestId>
</Error>

```

#### Request 5

**Request:**

```http
HEAD https://s3.stage.rabata.io/test-dagm-bucket-listversioning/dm-compare-5c00a921 HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061612Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 404
Content-Type: application/xml
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TYSQ8CR0FDY1VPV8HZWCB
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

#### Request 6

**Request:**

```http
GET https://s3.stage.rabata.io/test-dagm-bucket-listversioning/dm-compare-5c00a921?versionId=01KN3TYSQ8CR0FDY1VPV8HZWCB HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061613Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 405
Content-Type: application/xml
Content-Length: 215
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TYSQ8CR0FDY1VPV8HZWCB
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *

<Error>
  <Code>MethodNotAllowed</Code>
  <Message>The specified method is not allowed against this resource.</Message>
  <RequestId>7c922dfd4f9336ce5b6409559654ffa5</RequestId>
</Error>

```

#### Request 7

**Request:**

```http
HEAD https://s3.stage.rabata.io/test-dagm-bucket-listversioning/dm-compare-5c00a921?versionId=01KN3TYSQ8CR0FDY1VPV8HZWCB HTTP/1.1
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
X-Forwarded-Proto: https
Content-Length: 0
x-amz-content-sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X-Amz-Date: 20260401T061615Z
Authorization: [REDACTED]
```

**Response:**

```http
HTTP/1.1 405
Content-Type: application/xml
X-Amz-Delete-Marker: true
X-Amz-Version-Id: 01KN3TYSQ8CR0FDY1VPV8HZWCB
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, HEAD, DELETE
Access-Control-Allow-Headers: *
Access-Control-Expose-Headers: *
```

---
